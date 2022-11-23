/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2022 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package nncp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/dustin/go-humanize"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/poly1305"
)

const (
	SeenDir = "seen"
)

func jobPath2Seen(jobPath string) string {
	return filepath.Join(filepath.Dir(jobPath), SeenDir, filepath.Base(jobPath))
}

func newNotification(fromTo *FromToJSON, subject string, body []byte) io.Reader {
	lines := []string{
		"From: " + fromTo.From,
		"To: " + fromTo.To,
		"Subject: " + mime.BEncoding.Encode("UTF-8", subject),
	}
	if len(body) > 0 {
		lines = append(
			lines,
			"MIME-Version: 1.0",
			"Content-Type: text/plain; charset=utf-8",
			"Content-Transfer-Encoding: base64",
			"",
			base64.StdEncoding.EncodeToString(body),
		)
	}
	return strings.NewReader(strings.Join(lines, "\n"))
}

func pktSizeWithoutEnc(pktSize int64) int64 {
	pktSize = pktSize - PktEncOverhead - PktOverhead - PktSizeOverhead
	pktSizeBlocks := pktSize / (EncBlkSize + poly1305.TagSize)
	if pktSize%(EncBlkSize+poly1305.TagSize) != 0 {
		pktSize -= poly1305.TagSize
	}
	pktSize -= pktSizeBlocks * poly1305.TagSize
	return pktSize
}

var JobRepeatProcess = errors.New("needs processing repeat")

func jobProcess(
	ctx *Ctx,
	pipeR *io.PipeReader,
	pktName string,
	les LEs,
	sender *Node,
	nice uint8,
	pktSize uint64,
	jobPath string,
	decompressor *zstd.Decoder,
	dryRun, doSeen, noFile, noFreq, noExec, noTrns, noArea, noACK bool,
) error {
	defer pipeR.Close()
	sendmail := ctx.Neigh[*ctx.SelfId].Exec["sendmail"]
	var pkt Pkt
	_, err := xdr.Unmarshal(pipeR, &pkt)
	if err != nil {
		ctx.LogE("rx-unmarshal", les, err, func(les LEs) string {
			return fmt.Sprintf("Tossing %s/%s: unmarshal", sender.Name, pktName)
		})
		return err
	}
	les = append(les, LE{"Size", int64(pktSize)})
	ctx.LogD("rx", les, func(les LEs) string {
		return fmt.Sprintf(
			"Tossing %s/%s (%s)",
			sender.Name, pktName,
			humanize.IBytes(pktSize),
		)
	})
	switch pkt.Type {
	case PktTypeExec, PktTypeExecFat:
		if noExec {
			return nil
		}
		path := bytes.Split(pkt.Path[:int(pkt.PathLen)], []byte{0})
		handle := string(path[0])
		args := make([]string, 0, len(path)-1)
		for _, p := range path[1:] {
			args = append(args, string(p))
		}
		argsStr := strings.Join(append([]string{handle}, args...), " ")
		les = append(les, LE{"Type", "exec"}, LE{"Dst", argsStr})
		cmdline := sender.Exec[handle]
		if len(cmdline) == 0 {
			err = errors.New("No handle found")
			ctx.LogE(
				"rx-no-handle", les, err,
				func(les LEs) string {
					return fmt.Sprintf(
						"Tossing exec %s/%s (%s): %s",
						sender.Name, pktName,
						humanize.IBytes(pktSize), argsStr,
					)
				},
			)
			return err
		}
		if pkt.Type == PktTypeExec {
			if err = decompressor.Reset(pipeR); err != nil {
				log.Fatalln(err)
			}
		}
		if !dryRun {
			cmd := exec.Command(cmdline[0], append(cmdline[1:], args...)...)
			cmd.Env = append(
				cmd.Env,
				"NNCP_SELF="+ctx.Self.Id.String(),
				"NNCP_SENDER="+sender.Id.String(),
				"NNCP_NICE="+strconv.Itoa(int(pkt.Nice)),
			)
			if pkt.Type == PktTypeExec {
				cmd.Stdin = decompressor
			} else {
				cmd.Stdin = pipeR
			}
			output, err := cmd.CombinedOutput()
			if err != nil {
				les = append(les, LE{"Output", strings.Split(
					strings.Trim(string(output), "\n"), "\n"),
				})
				ctx.LogE("rx-handle", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing exec %s/%s (%s): %s: handling",
						sender.Name, pktName,
						humanize.IBytes(uint64(pktSize)), argsStr,
					)
				})
				return err
			}
			if len(sendmail) > 0 && ctx.NotifyExec != nil {
				notify := ctx.NotifyExec[sender.Name+"."+handle]
				if notify == nil {
					notify = ctx.NotifyExec["*."+handle]
				}
				if notify != nil {
					cmd := exec.Command(
						sendmail[0],
						append(sendmail[1:], notify.To)...,
					)
					cmd.Stdin = newNotification(notify, fmt.Sprintf(
						"Exec from %s: %s", sender.Name, argsStr,
					), output)
					if err = cmd.Run(); err != nil {
						ctx.LogE("rx-notify", les, err, func(les LEs) string {
							return fmt.Sprintf(
								"Tossing exec %s/%s (%s): %s: notifying",
								sender.Name, pktName,
								humanize.IBytes(pktSize), argsStr,
							)
						})
					}
				}
			}
		}
		ctx.LogI("rx", les, func(les LEs) string {
			return fmt.Sprintf(
				"Got exec from %s to %s (%s)",
				sender.Name, argsStr,
				humanize.IBytes(pktSize),
			)
		})
		if !dryRun && jobPath != "" {
			if doSeen {
				if err := ensureDir(filepath.Dir(jobPath), SeenDir); err != nil {
					return err
				}
				if fd, err := os.Create(jobPath2Seen(jobPath)); err == nil {
					fd.Close()
					if err = DirSync(filepath.Dir(jobPath)); err != nil {
						ctx.LogE("rx-dirsync", les, err, func(les LEs) string {
							return fmt.Sprintf(
								"Tossing file %s/%s (%s): %s: dirsyncing",
								sender.Name, pktName,
								humanize.IBytes(pktSize),
								filepath.Base(jobPath),
							)
						})
						return err
					}
				}
			}
			if err = os.Remove(jobPath); err != nil {
				ctx.LogE("rx-notify", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing exec %s/%s (%s): %s: notifying",
						sender.Name, pktName,
						humanize.IBytes(pktSize), argsStr,
					)
				})
				return err
			} else if ctx.HdrUsage {
				os.Remove(JobPath2Hdr(jobPath))
			}
		}

	case PktTypeFile:
		if noFile {
			return nil
		}
		dst := string(pkt.Path[:int(pkt.PathLen)])
		les = append(les, LE{"Type", "file"}, LE{"Dst", dst})
		if filepath.IsAbs(dst) {
			err = errors.New("non-relative destination path")
			ctx.LogE(
				"rx-non-rel", les, err,
				func(les LEs) string {
					return fmt.Sprintf(
						"Tossing file %s/%s (%s): %s",
						sender.Name, pktName,
						humanize.IBytes(pktSize), dst,
					)
				},
			)
			return err
		}
		incoming := sender.Incoming
		if incoming == nil {
			err = errors.New("incoming is not allowed")
			ctx.LogE(
				"rx-no-incoming", les, err,
				func(les LEs) string {
					return fmt.Sprintf(
						"Tossing file %s/%s (%s): %s",
						sender.Name, pktName,
						humanize.IBytes(pktSize), dst,
					)
				},
			)
			return err
		}
		dir := filepath.Join(*incoming, path.Dir(dst))
		if err = os.MkdirAll(dir, os.FileMode(0777)); err != nil {
			ctx.LogE("rx-mkdir", les, err, func(les LEs) string {
				return fmt.Sprintf(
					"Tossing file %s/%s (%s): %s: mkdir",
					sender.Name, pktName,
					humanize.IBytes(pktSize), dst,
				)
			})
			return err
		}
		if !dryRun {
			tmp, err := TempFile(dir, "file")
			if err != nil {
				ctx.LogE("rx-mktemp", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing file %s/%s (%s): %s: mktemp",
						sender.Name, pktName,
						humanize.IBytes(pktSize), dst,
					)
				})
				return err
			}
			les = append(les, LE{"Tmp", tmp.Name()})
			ctx.LogD("rx-tmp-created", les, func(les LEs) string {
				return fmt.Sprintf(
					"Tossing file %s/%s (%s): %s: created: %s",
					sender.Name, pktName,
					humanize.IBytes(pktSize), dst, tmp.Name(),
				)
			})
			bufW := bufio.NewWriter(tmp)
			if _, err = CopyProgressed(
				bufW, pipeR, "Rx file",
				append(les, LE{"FullSize", int64(pktSize)}),
				ctx.ShowPrgrs,
			); err != nil {
				ctx.LogE("rx-copy", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing file %s/%s (%s): %s: copying",
						sender.Name, pktName,
						humanize.IBytes(pktSize), dst,
					)
				})
				return err
			}
			if err = bufW.Flush(); err != nil {
				tmp.Close()
				ctx.LogE("rx-flush", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing file %s/%s (%s): %s: flushing",
						sender.Name, pktName,
						humanize.IBytes(pktSize), dst,
					)
				})
				return err
			}
			if !NoSync {
				if err = tmp.Sync(); err != nil {
					tmp.Close()
					ctx.LogE("rx-sync", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: syncing",
							sender.Name, pktName,
							humanize.IBytes(pktSize), dst,
						)
					})
					return err
				}
			}
			if err = tmp.Close(); err != nil {
				ctx.LogE("rx-close", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing file %s/%s (%s): %s: closing",
						sender.Name, pktName,
						humanize.IBytes(pktSize), dst,
					)
				})
				return err
			}
			dstPathOrig := filepath.Join(*incoming, dst)
			dstPath := dstPathOrig
			dstPathCtr := 0
			for {
				if _, err = os.Stat(dstPath); err != nil {
					if os.IsNotExist(err) {
						break
					}
					ctx.LogE("rx-stat", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: stating: %s",
							sender.Name, pktName,
							humanize.IBytes(pktSize), dst, dstPath,
						)
					})
					return err
				}
				dstPath = dstPathOrig + "." + strconv.Itoa(dstPathCtr)
				dstPathCtr++
			}
			if err = os.Rename(tmp.Name(), dstPath); err != nil {
				ctx.LogE("rx-rename", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing file %s/%s (%s): %s: renaming",
						sender.Name, pktName,
						humanize.IBytes(pktSize), dst,
					)
				})
				return err
			}
			if err = DirSync(*incoming); err != nil {
				ctx.LogE("rx-dirsync", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing file %s/%s (%s): %s: dirsyncing",
						sender.Name, pktName,
						humanize.IBytes(pktSize), dst,
					)
				})
				return err
			}
			les = les[:len(les)-1] // delete Tmp
		}
		ctx.LogI("rx", les, func(les LEs) string {
			return fmt.Sprintf(
				"Got file %s (%s) from %s",
				dst, humanize.IBytes(pktSize), sender.Name,
			)
		})
		if !dryRun {
			if jobPath != "" {
				if doSeen {
					if err := ensureDir(filepath.Dir(jobPath), SeenDir); err != nil {
						return err
					}
					if fd, err := os.Create(jobPath2Seen(jobPath)); err == nil {
						fd.Close()
						if err = DirSync(filepath.Dir(jobPath)); err != nil {
							ctx.LogE("rx-dirsync", les, err, func(les LEs) string {
								return fmt.Sprintf(
									"Tossing file %s/%s (%s): %s: dirsyncing",
									sender.Name, pktName,
									humanize.IBytes(pktSize),
									filepath.Base(jobPath),
								)
							})
							return err
						}
					}
				}
				if err = os.Remove(jobPath); err != nil {
					ctx.LogE("rx-remove", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: removing",
							sender.Name, pktName,
							humanize.IBytes(pktSize), dst,
						)
					})
					return err
				} else if ctx.HdrUsage {
					os.Remove(JobPath2Hdr(jobPath))
				}
			}
			if len(sendmail) > 0 && ctx.NotifyFile != nil {
				cmd := exec.Command(
					sendmail[0],
					append(sendmail[1:], ctx.NotifyFile.To)...,
				)
				cmd.Stdin = newNotification(ctx.NotifyFile, fmt.Sprintf(
					"File from %s: %s (%s)",
					sender.Name, dst, humanize.IBytes(pktSize),
				), nil)
				if err = cmd.Run(); err != nil {
					ctx.LogE("rx-notify", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: notifying",
							sender.Name, pktName,
							humanize.IBytes(pktSize), dst,
						)
					})
				}
			}
		}

	case PktTypeFreq:
		if noFreq {
			return nil
		}
		src := string(pkt.Path[:int(pkt.PathLen)])
		les := append(les, LE{"Type", "freq"}, LE{"Src", src})
		if filepath.IsAbs(src) {
			err = errors.New("non-relative source path")
			ctx.LogE(
				"rx-non-rel", les, err,
				func(les LEs) string {
					return fmt.Sprintf(
						"Tossing freq %s/%s (%s): %s: notifying",
						sender.Name, pktName,
						humanize.IBytes(pktSize), src,
					)
				},
			)
			return err
		}
		dstRaw, err := ioutil.ReadAll(pipeR)
		if err != nil {
			ctx.LogE("rx-read", les, err, func(les LEs) string {
				return fmt.Sprintf(
					"Tossing freq %s/%s (%s): %s: reading",
					sender.Name, pktName,
					humanize.IBytes(pktSize), src,
				)
			})
			return err
		}
		dst := string(dstRaw)
		les = append(les, LE{"Dst", dst})
		freqPath := sender.FreqPath
		if freqPath == nil {
			err = errors.New("freqing is not allowed")
			ctx.LogE(
				"rx-no-freq", les, err,
				func(les LEs) string {
					return fmt.Sprintf(
						"Tossing freq %s/%s (%s): %s -> %s",
						sender.Name, pktName,
						humanize.IBytes(pktSize), src, dst,
					)
				},
			)
			return err
		}
		if !dryRun {
			err = ctx.TxFile(
				sender,
				pkt.Nice,
				filepath.Join(*freqPath, src),
				dst,
				sender.FreqChunked,
				sender.FreqMinSize,
				sender.FreqMaxSize,
				nil,
			)
			if err != nil {
				ctx.LogE("rx-tx", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing freq %s/%s (%s): %s -> %s: txing",
						sender.Name, pktName,
						humanize.IBytes(pktSize), src, dst,
					)
				})
				return err
			}
		}
		ctx.LogI("rx", les, func(les LEs) string {
			return fmt.Sprintf("Got file request %s to %s", src, sender.Name)
		})
		if !dryRun {
			if jobPath != "" {
				if doSeen {
					if err := ensureDir(filepath.Dir(jobPath), SeenDir); err != nil {
						return err
					}
					if fd, err := os.Create(jobPath2Seen(jobPath)); err == nil {
						fd.Close()
						if err = DirSync(filepath.Dir(jobPath)); err != nil {
							ctx.LogE("rx-dirsync", les, err, func(les LEs) string {
								return fmt.Sprintf(
									"Tossing file %s/%s (%s): %s: dirsyncing",
									sender.Name, pktName,
									humanize.IBytes(pktSize),
									filepath.Base(jobPath),
								)
							})
							return err
						}
					}
				}
				if err = os.Remove(jobPath); err != nil {
					ctx.LogE("rx-remove", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing freq %s/%s (%s): %s -> %s: removing",
							sender.Name, pktName,
							humanize.IBytes(pktSize), src, dst,
						)
					})
					return err
				} else if ctx.HdrUsage {
					os.Remove(JobPath2Hdr(jobPath))
				}
			}
			if len(sendmail) > 0 && ctx.NotifyFreq != nil {
				cmd := exec.Command(
					sendmail[0],
					append(sendmail[1:], ctx.NotifyFreq.To)...,
				)
				cmd.Stdin = newNotification(ctx.NotifyFreq, fmt.Sprintf(
					"Freq from %s: %s", sender.Name, src,
				), nil)
				if err = cmd.Run(); err != nil {
					ctx.LogE("rx-notify", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing freq %s/%s (%s): %s -> %s: notifying",
							sender.Name, pktName,
							humanize.IBytes(pktSize), src, dst,
						)
					})
				}
			}
		}

	case PktTypeTrns:
		if noTrns {
			return nil
		}
		dst := new([MTHSize]byte)
		copy(dst[:], pkt.Path[:int(pkt.PathLen)])
		nodeId := NodeId(*dst)
		les := append(les, LE{"Type", "trns"}, LE{"Dst", nodeId})
		logMsg := func(les LEs) string {
			return fmt.Sprintf(
				"Tossing trns %s/%s (%s): %s",
				sender.Name, pktName,
				humanize.IBytes(pktSize),
				nodeId.String(),
			)
		}
		node := ctx.Neigh[nodeId]
		if node == nil {
			err = errors.New("unknown node")
			ctx.LogE("rx-unknown", les, err, logMsg)
			return err
		}
		ctx.LogD("rx-tx", les, logMsg)
		if !dryRun {
			if len(node.Via) == 0 {
				if err = ctx.TxTrns(node, nice, int64(pktSize), pipeR); err != nil {
					ctx.LogE("rx", les, err, func(les LEs) string {
						return logMsg(les) + ": txing"
					})
					return err
				}
			} else {
				via := node.Via[:len(node.Via)-1]
				node = ctx.Neigh[*node.Via[len(node.Via)-1]]
				node = &Node{Id: node.Id, Via: via, ExchPub: node.ExchPub}
				pktTrns, err := NewPkt(PktTypeTrns, 0, nodeId[:])
				if err != nil {
					panic(err)
				}
				if _, _, _, err = ctx.Tx(
					node,
					pktTrns,
					nice,
					int64(pktSize), 0, MaxFileSize,
					pipeR,
					pktName,
					nil,
				); err != nil {
					ctx.LogE("rx", les, err, func(les LEs) string {
						return logMsg(les) + ": txing"
					})
					return err
				}
			}
		}
		ctx.LogI("rx", les, func(les LEs) string {
			return fmt.Sprintf(
				"Got transitional packet from %s to %s (%s)",
				sender.Name,
				ctx.NodeName(&nodeId),
				humanize.IBytes(pktSize),
			)
		})
		if !dryRun && jobPath != "" {
			if doSeen {
				if err := ensureDir(filepath.Dir(jobPath), SeenDir); err != nil {
					return err
				}
				if fd, err := os.Create(jobPath2Seen(jobPath)); err == nil {
					fd.Close()
					if err = DirSync(filepath.Dir(jobPath)); err != nil {
						ctx.LogE("rx-dirsync", les, err, func(les LEs) string {
							return fmt.Sprintf(
								"Tossing file %s/%s (%s): %s: dirsyncing",
								sender.Name, pktName,
								humanize.IBytes(pktSize),
								filepath.Base(jobPath),
							)
						})
						return err
					}
				}
			}
			if err = os.Remove(jobPath); err != nil {
				ctx.LogE("rx", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing trns %s/%s (%s): %s: removing",
						sender.Name, pktName,
						humanize.IBytes(pktSize),
						ctx.NodeName(&nodeId),
					)
				})
				return err
			} else if ctx.HdrUsage {
				os.Remove(JobPath2Hdr(jobPath))
			}
		}

	case PktTypeArea:
		if noArea {
			return nil
		}
		areaId := new(AreaId)
		copy(areaId[:], pkt.Path[:int(pkt.PathLen)])
		les := append(les, LE{"Type", "area"}, LE{"Area", areaId})
		logMsg := func(les LEs) string {
			return fmt.Sprintf(
				"Tossing %s/%s (%s): area %s",
				sender.Name, pktName,
				humanize.IBytes(pktSize),
				ctx.AreaName(areaId),
			)
		}
		area := ctx.AreaId2Area[*areaId]
		if area == nil {
			err = errors.New("unknown area")
			ctx.LogE("rx-area-unknown", les, err, logMsg)
			return err
		}
		pktEnc, pktEncRaw, err := ctx.HdrRead(pipeR)
		fullPipeR := io.MultiReader(bytes.NewReader(pktEncRaw), pipeR)
		if err != nil {
			ctx.LogE("rx-area-pkt-enc-read", les, err, logMsg)
			return err
		}
		msgHashRaw := blake2b.Sum256(pktEncRaw)
		msgHash := Base32Codec.EncodeToString(msgHashRaw[:])
		les = append(les, LE{"AreaMsg", msgHash})
		ctx.LogD("rx-area", les, logMsg)

		if dryRun {
			for _, nodeId := range area.Subs {
				node := ctx.Neigh[*nodeId]
				lesEcho := append(les, LE{"Echo", nodeId})
				seenDir := filepath.Join(
					ctx.Spool, nodeId.String(), AreaDir, area.Id.String(),
				)
				seenPath := filepath.Join(seenDir, msgHash)
				logMsgNode := func(les LEs) string {
					return fmt.Sprintf(
						"%s: echoing to: %s", logMsg(les), node.Name,
					)
				}
				if _, err := os.Stat(seenPath); err == nil {
					ctx.LogD("rx-area-echo-seen", lesEcho, func(les LEs) string {
						return logMsgNode(les) + ": already sent"
					})
					continue
				}
				ctx.LogI("rx-area-echo", lesEcho, logMsgNode)
			}
		} else {
			for _, nodeId := range area.Subs {
				node := ctx.Neigh[*nodeId]
				lesEcho := append(les, LE{"Echo", nodeId})
				seenDir := filepath.Join(
					ctx.Spool, nodeId.String(), AreaDir, area.Id.String(),
				)
				seenPath := filepath.Join(seenDir, msgHash)
				logMsgNode := func(les LEs) string {
					return fmt.Sprintf("%s: echo to: %s", logMsg(les), node.Name)
				}
				if _, err := os.Stat(seenPath); err == nil {
					ctx.LogD("rx-area-echo-seen", lesEcho, func(les LEs) string {
						return logMsgNode(les) + ": already sent"
					})
					continue
				}
				if nodeId != sender.Id && nodeId != pktEnc.Sender {
					ctx.LogI("rx-area-echo", lesEcho, logMsgNode)
					if _, _, _, err = ctx.Tx(
						node,
						&pkt,
						nice,
						int64(pktSize), 0, MaxFileSize,
						fullPipeR,
						pktName,
						nil,
					); err != nil {
						ctx.LogE("rx-area", lesEcho, err, logMsgNode)
						return err
					}
				}
				if err = os.MkdirAll(seenDir, os.FileMode(0777)); err != nil {
					ctx.LogE("rx-area-mkdir", lesEcho, err, logMsgNode)
					return err
				}
				if fd, err := os.Create(seenPath); err == nil {
					fd.Close()
					if err = DirSync(seenDir); err != nil {
						ctx.LogE("rx-area-dirsync", les, err, logMsgNode)
						return err
					}
				} else {
					ctx.LogE("rx-area-touch", lesEcho, err, logMsgNode)
					return err
				}
				return JobRepeatProcess
			}
		}

		seenDir := filepath.Join(
			ctx.Spool, ctx.SelfId.String(), AreaDir, area.Id.String(),
		)
		seenPath := filepath.Join(seenDir, msgHash)
		if _, err := os.Stat(seenPath); err == nil {
			ctx.LogD("rx-area-seen", les, func(les LEs) string {
				return logMsg(les) + ": already seen"
			})
			if !dryRun && jobPath != "" {
				if err = os.Remove(jobPath); err != nil {
					ctx.LogE("rx-area-remove", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing area %s/%s (%s): %s: removing",
							sender.Name, pktName,
							humanize.IBytes(pktSize),
							msgHash,
						)
					})
					return err
				} else if ctx.HdrUsage {
					os.Remove(JobPath2Hdr(jobPath))
				}
			}
			return nil
		}

		if area.Prv == nil {
			ctx.LogD("rx-area-no-prv", les, func(les LEs) string {
				return logMsg(les) + ": no private key for decoding"
			})
		} else {
			signatureVerify := true
			if _, senderKnown := ctx.Neigh[*pktEnc.Sender]; !senderKnown {
				if !area.AllowUnknown {
					err = errors.New("unknown sender")
					ctx.LogE(
						"rx-area-unknown",
						append(les, LE{"Sender", pktEnc.Sender}),
						err,
						func(les LEs) string {
							return logMsg(les) + ": sender: " + pktEnc.Sender.String()
						},
					)
					return err
				}
				signatureVerify = false
			}
			areaNodeOur := NodeOur{Id: new(NodeId), ExchPrv: new([32]byte)}
			copy(areaNodeOur.Id[:], area.Id[:])
			copy(areaNodeOur.ExchPrv[:], area.Prv[:])
			areaNode := Node{
				Id:       new(NodeId),
				Name:     area.Name,
				Incoming: area.Incoming,
				Exec:     area.Exec,
			}
			copy(areaNode.Id[:], area.Id[:])
			pktName := fmt.Sprintf(
				"area/%s/%s",
				Base32Codec.EncodeToString(areaId[:]), msgHash,
			)

			pipeR, pipeW := io.Pipe()
			errs := make(chan error, 1)
			go func() {
				errs <- jobProcess(
					ctx,
					pipeR,
					pktName,
					les,
					&areaNode,
					nice,
					uint64(pktSizeWithoutEnc(int64(pktSize))),
					"",
					decompressor,
					dryRun, doSeen, noFile, noFreq, noExec, noTrns, noArea, noACK,
				)
			}()
			_, _, _, err = PktEncRead(
				&areaNodeOur,
				ctx.Neigh,
				fullPipeR,
				pipeW,
				signatureVerify,
				nil,
			)
			if err != nil {
				ctx.LogE("rx-area-pkt-enc-read2", les, err, logMsg)
				pipeW.CloseWithError(err)
				<-errs
				return err
			}
			pipeW.Close()
			if err = <-errs; err != nil {
				return err
			}
		}

		if !dryRun && jobPath != "" {
			if err = os.MkdirAll(seenDir, os.FileMode(0777)); err != nil {
				ctx.LogE("rx-area-mkdir", les, err, logMsg)
				return err
			}
			if fd, err := os.Create(seenPath); err == nil {
				fd.Close()
				if err = DirSync(seenDir); err != nil {
					ctx.LogE("rx-area-dirsync", les, err, logMsg)
					return err
				}
			}
			if err = os.Remove(jobPath); err != nil {
				ctx.LogE("rx", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing area %s/%s (%s): %s: removing",
						sender.Name, pktName,
						humanize.IBytes(pktSize),
						msgHash,
					)
				})
				return err
			} else if ctx.HdrUsage {
				os.Remove(JobPath2Hdr(jobPath))
			}
		}

	case PktTypeACK:
		if noACK {
			return nil
		}
		hsh := Base32Codec.EncodeToString(pkt.Path[:MTHSize])
		les := append(les, LE{"Type", "ack"}, LE{"Pkt", hsh})
		logMsg := func(les LEs) string {
			return fmt.Sprintf("Tossing ack %s/%s: %s", sender.Name, pktName, hsh)
		}
		ctx.LogD("rx-ack", les, logMsg)
		pktPath := filepath.Join(ctx.Spool, sender.Id.String(), string(TTx), hsh)
		if _, err := os.Stat(pktPath); err == nil {
			if !dryRun {
				if err = os.Remove(pktPath); err != nil {
					ctx.LogE("rx-ack", les, err, func(les LEs) string {
						return logMsg(les) + ": removing packet"
					})
					return err
				} else if ctx.HdrUsage {
					os.Remove(JobPath2Hdr(pktPath))
				}
			}
		} else {
			ctx.LogD("rx-ack", les, func(les LEs) string {
				return logMsg(les) + ": already disappeared"
			})
		}
		if !dryRun && doSeen {
			if err := ensureDir(filepath.Dir(jobPath), SeenDir); err != nil {
				return err
			}
			if fd, err := os.Create(jobPath2Seen(jobPath)); err == nil {
				fd.Close()
				if err = DirSync(filepath.Dir(jobPath)); err != nil {
					ctx.LogE("rx-dirsync", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: dirsyncing",
							sender.Name, pktName,
							humanize.IBytes(pktSize),
							filepath.Base(jobPath),
						)
					})
					return err
				}
			}
		}
		if !dryRun {
			if err = os.Remove(jobPath); err != nil {
				ctx.LogE("rx", les, err, func(les LEs) string {
					return logMsg(les) + ": removing job"
				})
				return err
			} else if ctx.HdrUsage {
				os.Remove(JobPath2Hdr(jobPath))
			}
		}
		ctx.LogI("rx", les, func(les LEs) string {
			return fmt.Sprintf("Got ACK packet from %s of %s", sender.Name, hsh)
		})

	default:
		err = errors.New("unknown type")
		ctx.LogE(
			"rx-type-unknown", les, err,
			func(les LEs) string {
				return fmt.Sprintf(
					"Tossing %s/%s (%s)",
					sender.Name, pktName, humanize.IBytes(pktSize),
				)
			},
		)
		return err
	}
	return nil
}

func (ctx *Ctx) Toss(
	nodeId *NodeId,
	xx TRxTx,
	nice uint8,
	dryRun, doSeen, noFile, noFreq, noExec, noTrns, noArea, noACK bool,
) bool {
	dirLock, err := ctx.LockDir(nodeId, "toss")
	if err != nil {
		return false
	}
	defer ctx.UnlockDir(dirLock)
	isBad := false
	decompressor, err := zstd.NewReader(nil)
	if err != nil {
		panic(err)
	}
	defer decompressor.Close()
	for job := range ctx.Jobs(nodeId, xx) {
		pktName := filepath.Base(job.Path)
		les := LEs{
			{"Node", job.PktEnc.Sender},
			{"Pkt", pktName},
			{"Nice", int(job.PktEnc.Nice)},
		}
		if job.PktEnc.Nice > nice {
			ctx.LogD("rx-too-nice", les, func(les LEs) string {
				return fmt.Sprintf(
					"Tossing %s/%s: too nice: %s",
					ctx.NodeName(job.PktEnc.Sender), pktName,
					NicenessFmt(job.PktEnc.Nice),
				)
			})
			continue
		}
		fd, err := os.Open(job.Path)
		if err != nil {
			ctx.LogE("rx-open", les, err, func(les LEs) string {
				return fmt.Sprintf(
					"Tossing %s/%s: opening %s",
					ctx.NodeName(job.PktEnc.Sender), pktName, job.Path,
				)
			})
			isBad = true
			continue
		}
		sender := ctx.Neigh[*job.PktEnc.Sender]
		if sender == nil {
			err := errors.New("unknown node")
			ctx.LogE("rx-open", les, err, func(les LEs) string {
				return fmt.Sprintf(
					"Tossing %s/%s",
					ctx.NodeName(job.PktEnc.Sender), pktName,
				)
			})
			isBad = true
			continue
		}
		errs := make(chan error, 1)
		var sharedKey []byte
	Retry:
		pipeR, pipeW := io.Pipe()
		go func() {
			errs <- jobProcess(
				ctx,
				pipeR,
				pktName,
				les,
				sender,
				job.PktEnc.Nice,
				uint64(pktSizeWithoutEnc(job.Size)),
				job.Path,
				decompressor,
				dryRun, doSeen, noFile, noFreq, noExec, noTrns, noArea, noACK,
			)
		}()
		pipeWB := bufio.NewWriter(pipeW)
		sharedKey, _, _, err = PktEncRead(
			ctx.Self,
			ctx.Neigh,
			bufio.NewReaderSize(fd, MTHBlockSize),
			pipeWB,
			sharedKey == nil,
			sharedKey,
		)
		if err != nil {
			pipeW.CloseWithError(err)
		}
		if err := pipeWB.Flush(); err != nil {
			pipeW.CloseWithError(err)
		}
		pipeW.Close()

		if err != nil {
			isBad = true
			fd.Close()
			<-errs
			continue
		}
		if err = <-errs; err == JobRepeatProcess {
			if _, err = fd.Seek(0, io.SeekStart); err != nil {
				ctx.LogE("rx-seek", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing %s/%s: can not seek",
						ctx.NodeName(job.PktEnc.Sender),
						pktName,
					)
				})
				isBad = true
				break
			}
			goto Retry
		} else if err != nil {
			isBad = true
		}
		fd.Close()
	}
	return isBad
}

func (ctx *Ctx) AutoToss(
	nodeId *NodeId,
	nice uint8,
	doSeen, noFile, noFreq, noExec, noTrns, noArea, noACK bool,
) (chan struct{}, chan bool) {
	dw, err := ctx.NewDirWatcher(
		filepath.Join(ctx.Spool, nodeId.String(), string(TRx)),
		time.Second,
	)
	if err != nil {
		log.Fatalln(err)
	}
	finish := make(chan struct{})
	badCode := make(chan bool)
	go func() {
		bad := false
		for {
			select {
			case <-finish:
				dw.Close()
				badCode <- bad
				return
			case <-dw.C:
				bad = !ctx.Toss(
					nodeId, TRx, nice, false,
					doSeen, noFile, noFreq, noExec, noTrns, noArea, noACK) || bad
			}
		}
	}()
	return finish, badCode
}
