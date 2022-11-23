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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func cfgDirMkdir(dst ...string) error {
	return os.MkdirAll(filepath.Join(dst...), os.FileMode(0777))
}

func cfgDirSave(v interface{}, dst ...string) error {
	var r string
	switch v := v.(type) {
	case *string:
		if v == nil {
			return nil
		}
		r = *v
	case string:
		r = v
	case *int:
		if v == nil {
			return nil
		}
		r = strconv.Itoa(*v)
	case *uint:
		if v == nil {
			return nil
		}
		r = strconv.Itoa(int(*v))
	case *uint64:
		if v == nil {
			return nil
		}
		r = strconv.FormatUint(*v, 10)
	case int:
		r = strconv.Itoa(v)
	default:
		panic("unsupported value type")
	}
	mode := os.FileMode(0666)
	if strings.HasSuffix(dst[len(dst)-1], "prv") {
		mode = os.FileMode(0600)
	}
	return ioutil.WriteFile(filepath.Join(dst...), []byte(r+"\n"), mode)
}

func cfgDirTouch(dst ...string) error {
	if fd, err := os.Create(filepath.Join(dst...)); err == nil {
		fd.Close()
	} else {
		return err
	}
	return nil
}

func CfgToDir(dst string, cfg *CfgJSON) (err error) {
	if err = cfgDirMkdir(dst); err != nil {
		return
	}
	if err = cfgDirSave(cfg.Spool, dst, "spool"); err != nil {
		return
	}
	if err = cfgDirSave(cfg.Log, dst, "log"); err != nil {
		return
	}
	if err = cfgDirSave(cfg.Umask, dst, "umask"); err != nil {
		return
	}
	if cfg.OmitPrgrs {
		if err = cfgDirTouch(dst, "noprogress"); err != nil {
			return
		}
	}
	if cfg.NoHdr {
		if err = cfgDirTouch(dst, "nohdr"); err != nil {
			return
		}
	}

	if len(cfg.MCDRxIfis) > 0 {
		if err = cfgDirSave(
			strings.Join(cfg.MCDRxIfis, "\n"),
			dst, "mcd-listen",
		); err != nil {
			return
		}
	}
	if len(cfg.MCDTxIfis) > 0 {
		if err = cfgDirMkdir(dst, "mcd-send"); err != nil {
			return
		}
		for ifi, t := range cfg.MCDTxIfis {
			if err = cfgDirSave(t, dst, "mcd-send", ifi); err != nil {
				return
			}
		}
	}

	if cfg.Notify != nil {
		if cfg.Notify.File != nil {
			if err = cfgDirMkdir(dst, "notify", "file"); err != nil {
				return
			}
			if err = cfgDirSave(
				cfg.Notify.File.From,
				dst, "notify", "file", "from",
			); err != nil {
				return
			}
			if err = cfgDirSave(
				cfg.Notify.File.To,
				dst, "notify", "file", "to",
			); err != nil {
				return
			}
		}
		if cfg.Notify.Freq != nil {
			if err = cfgDirMkdir(dst, "notify", "freq"); err != nil {
				return
			}
			if err = cfgDirSave(
				cfg.Notify.Freq.From,
				dst, "notify", "freq", "from",
			); err != nil {
				return
			}
			if err = cfgDirSave(
				cfg.Notify.Freq.To,
				dst, "notify", "freq", "to",
			); err != nil {
				return
			}
		}
		for k, v := range cfg.Notify.Exec {
			if err = cfgDirMkdir(dst, "notify", "exec", k); err != nil {
				return
			}
			if err = cfgDirSave(v.From, dst, "notify", "exec", k, "from"); err != nil {
				return
			}
			if err = cfgDirSave(v.To, dst, "notify", "exec", k, "to"); err != nil {
				return
			}
		}
	}

	if cfg.Self != nil {
		if err = cfgDirMkdir(dst, "self"); err != nil {
			return
		}
		if err = cfgDirSave(cfg.Self.Id, dst, "self", "id"); err != nil {
			return
		}
		if err = cfgDirSave(cfg.Self.ExchPub, dst, "self", "exchpub"); err != nil {
			return
		}
		if err = cfgDirSave(cfg.Self.ExchPrv, dst, "self", "exchprv"); err != nil {
			return
		}
		if err = cfgDirSave(cfg.Self.SignPub, dst, "self", "signpub"); err != nil {
			return
		}
		if err = cfgDirSave(cfg.Self.SignPrv, dst, "self", "signprv"); err != nil {
			return
		}
		if err = cfgDirSave(cfg.Self.NoisePub, dst, "self", "noisepub"); err != nil {
			return
		}
		if err = cfgDirSave(cfg.Self.NoisePrv, dst, "self", "noiseprv"); err != nil {
			return
		}
	}

	for name, n := range cfg.Neigh {
		if err = cfgDirMkdir(dst, "neigh", name); err != nil {
			return
		}
		if err = cfgDirSave(n.Id, dst, "neigh", name, "id"); err != nil {
			return
		}
		if err = cfgDirSave(n.ExchPub, dst, "neigh", name, "exchpub"); err != nil {
			return
		}
		if err = cfgDirSave(n.SignPub, dst, "neigh", name, "signpub"); err != nil {
			return
		}
		if err = cfgDirSave(n.NoisePub, dst, "neigh", name, "noisepub"); err != nil {
			return
		}
		if err = cfgDirSave(n.Incoming, dst, "neigh", name, "incoming"); err != nil {
			return
		}

		if len(n.Exec) > 0 {
			if err = cfgDirMkdir(dst, "neigh", name, "exec"); err != nil {
				return
			}
			for k, v := range n.Exec {
				if err = cfgDirSave(
					strings.Join(v, "\n"),
					dst, "neigh", name, "exec", k,
				); err != nil {
					return
				}
			}
		}

		if n.Freq != nil {
			if err = cfgDirMkdir(dst, "neigh", name, "freq"); err != nil {
				return
			}
			if err = cfgDirSave(
				n.Freq.Path,
				dst, "neigh", name, "freq", "path",
			); err != nil {
				return
			}
			if err = cfgDirSave(
				n.Freq.Chunked,
				dst, "neigh", name, "freq", "chunked",
			); err != nil {
				return
			}
			if err = cfgDirSave(
				n.Freq.MinSize,
				dst, "neigh", name, "freq", "minsize",
			); err != nil {
				return
			}
			if err = cfgDirSave(
				n.Freq.MaxSize,
				dst, "neigh", name, "freq", "maxsize",
			); err != nil {
				return
			}
		}

		if len(n.Via) > 0 {
			if err = cfgDirSave(
				strings.Join(n.Via, "\n"),
				dst, "neigh", name, "via",
			); err != nil {
				return
			}
		}

		if len(n.Addrs) > 0 {
			if err = cfgDirMkdir(dst, "neigh", name, "addrs"); err != nil {
				return
			}
			for k, v := range n.Addrs {
				if err = cfgDirSave(v, dst, "neigh", name, "addrs", k); err != nil {
					return
				}
			}
		}

		if err = cfgDirSave(n.RxRate, dst, "neigh", name, "rxrate"); err != nil {
			return
		}
		if err = cfgDirSave(n.TxRate, dst, "neigh", name, "txrate"); err != nil {
			return
		}
		if err = cfgDirSave(n.OnlineDeadline, dst, "neigh", name, "onlinedeadline"); err != nil {
			return
		}
		if err = cfgDirSave(n.MaxOnlineTime, dst, "neigh", name, "maxonlinetime"); err != nil {
			return
		}

		for i, call := range n.Calls {
			is := strconv.Itoa(i)
			if err = cfgDirMkdir(dst, "neigh", name, "calls", is); err != nil {
				return
			}
			if err = cfgDirSave(call.Cron, dst, "neigh", name, "calls", is, "cron"); err != nil {
				return
			}
			if err = cfgDirSave(call.Nice, dst, "neigh", name, "calls", is, "nice"); err != nil {
				return
			}
			if err = cfgDirSave(call.Xx, dst, "neigh", name, "calls", is, "xx"); err != nil {
				return
			}
			if err = cfgDirSave(call.RxRate, dst, "neigh", name, "calls", is, "rxrate"); err != nil {
				return
			}
			if err = cfgDirSave(call.TxRate, dst, "neigh", name, "calls", is, "txrate"); err != nil {
				return
			}
			if err = cfgDirSave(call.Addr, dst, "neigh", name, "calls", is, "addr"); err != nil {
				return
			}
			if err = cfgDirSave(call.OnlineDeadline, dst, "neigh", name, "calls", is, "onlinedeadline"); err != nil {
				return
			}
			if err = cfgDirSave(call.MaxOnlineTime, dst, "neigh", name, "calls", is, "maxonlinetime"); err != nil {
				return
			}
			if call.WhenTxExists {
				if err = cfgDirTouch(dst, "neigh", name, "calls", is, "when-tx-exists"); err != nil {
					return
				}
			}
			if call.NoCK {
				if err = cfgDirTouch(dst, "neigh", name, "calls", is, "nock"); err != nil {
					return
				}
			}
			if call.MCDIgnore {
				if err = cfgDirTouch(dst, "neigh", name, "calls", is, "mcd-ignore"); err != nil {
					return
				}
			}
			if call.AutoToss {
				if err = cfgDirTouch(dst, "neigh", name, "calls", is, "autotoss"); err != nil {
					return
				}
			}
			if call.AutoTossDoSeen {
				if err = cfgDirTouch(dst, "neigh", name, "calls", is, "autotoss-doseen"); err != nil {
					return
				}
			}
			if call.AutoTossNoFile {
				if err = cfgDirTouch(dst, "neigh", name, "calls", is, "autotoss-nofile"); err != nil {
					return
				}
			}
			if call.AutoTossNoFreq {
				if err = cfgDirTouch(dst, "neigh", name, "calls", is, "autotoss-nofreq"); err != nil {
					return
				}
			}
			if call.AutoTossNoExec {
				if err = cfgDirTouch(dst, "neigh", name, "calls", is, "autotoss-noexec"); err != nil {
					return
				}
			}
			if call.AutoTossNoTrns {
				if err = cfgDirTouch(dst, "neigh", name, "calls", is, "autotoss-notrns"); err != nil {
					return
				}
			}
			if call.AutoTossNoArea {
				if err = cfgDirTouch(dst, "neigh", name, "calls", is, "autotoss-noarea"); err != nil {
					return
				}
			}
		}
	}

	for name, a := range cfg.Areas {
		if err = cfgDirMkdir(dst, "areas", name); err != nil {
			return
		}
		if err = cfgDirSave(a.Id, dst, "areas", name, "id"); err != nil {
			return
		}
		if err = cfgDirSave(a.Pub, dst, "areas", name, "pub"); err != nil {
			return
		}
		if err = cfgDirSave(a.Prv, dst, "areas", name, "prv"); err != nil {
			return
		}
		if err = cfgDirSave(a.Incoming, dst, "areas", name, "incoming"); err != nil {
			return
		}
		if a.AllowUnknown {
			if err = cfgDirTouch(dst, "areas", name, "allow-unknown"); err != nil {
				return
			}
		}
		if len(a.Exec) > 0 {
			if err = cfgDirMkdir(dst, "areas", name, "exec"); err != nil {
				return
			}
			for k, v := range a.Exec {
				if err = cfgDirSave(
					strings.Join(v, "\n"),
					dst, "areas", name, "exec", k,
				); err != nil {
					return
				}
			}
		}
		if len(a.Subs) > 0 {
			if err = cfgDirSave(
				strings.Join(a.Subs, "\n"),
				dst, "areas", name, "subs",
			); err != nil {
				return
			}
		}
	}

	if len(cfg.YggdrasilAliases) > 0 {
		if err = cfgDirMkdir(dst, "yggdrasil-aliases"); err != nil {
			return
		}
		for alias, v := range cfg.YggdrasilAliases {
			if err = cfgDirSave(v, dst, "yggdrasil-aliases", alias); err != nil {
				return
			}
		}
	}

	return
}

func cfgDirLoad(src ...string) (v string, exists bool, err error) {
	b, err := ioutil.ReadFile(filepath.Join(src...))
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return strings.TrimSuffix(string(b), "\n"), true, nil
}

func cfgDirLoadMust(src ...string) (v string, err error) {
	s, exists, err := cfgDirLoad(src...)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("required \"%s\" does not exist", src[len(src)-1])
	}
	return s, nil
}

func cfgDirLoadOpt(src ...string) (v *string, err error) {
	s, exists, err := cfgDirLoad(src...)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return &s, nil
}

func cfgDirLoadIntOpt(src ...string) (i64 *int64, err error) {
	s, err := cfgDirLoadOpt(src...)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, nil
	}
	i, err := strconv.ParseInt(*s, 10, 64)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

func cfgDirExists(src ...string) bool {
	if _, err := os.Stat(filepath.Join(src...)); err == nil {
		return true
	}
	return false
}

func cfgDirReadFromTo(src ...string) (*FromToJSON, error) {
	fromTo := FromToJSON{}

	var err error
	fromTo.From, err = cfgDirLoadMust(append(src, "from")...)
	if err != nil {
		return nil, err
	}

	fromTo.To, err = cfgDirLoadMust(append(src, "to")...)
	if err != nil {
		return nil, err
	}

	return &fromTo, nil
}

func DirToCfg(src string) (*CfgJSON, error) {
	cfg := CfgJSON{}
	var err error

	cfg.Spool, err = cfgDirLoadMust(src, "spool")
	if err != nil {
		return nil, err
	}
	cfg.Log, err = cfgDirLoadMust(src, "log")
	if err != nil {
		return nil, err
	}

	if cfg.Umask, err = cfgDirLoadOpt(src, "umask"); err != nil {
		return nil, err
	}
	cfg.OmitPrgrs = cfgDirExists(src, "noprogress")
	cfg.NoHdr = cfgDirExists(src, "nohdr")

	sp, err := cfgDirLoadOpt(src, "mcd-listen")
	if err != nil {
		return nil, err
	}
	if sp != nil {
		cfg.MCDRxIfis = strings.Split(*sp, "\n")
	}

	fis, err := ioutil.ReadDir(filepath.Join(src, "mcd-send"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(fis) > 0 {
		cfg.MCDTxIfis = make(map[string]int, len(fis))
	}
	for _, fi := range fis {
		n := fi.Name()
		if n[0] == '.' {
			continue
		}
		b, err := ioutil.ReadFile(filepath.Join(src, "mcd-send", fi.Name()))
		if err != nil {
			return nil, err
		}
		i, err := strconv.Atoi(strings.TrimSuffix(string(b), "\n"))
		if err != nil {
			return nil, err
		}
		cfg.MCDTxIfis[n] = i
	}

	notify := NotifyJSON{Exec: make(map[string]*FromToJSON)}
	if cfgDirExists(src, "notify", "file") {
		if notify.File, err = cfgDirReadFromTo(src, "notify", "file"); err != nil {
			return nil, err
		}
	}
	if cfgDirExists(src, "notify", "freq") {
		if notify.Freq, err = cfgDirReadFromTo(src, "notify", "freq"); err != nil {
			return nil, err
		}
	}
	fis, err = ioutil.ReadDir(filepath.Join(src, "notify", "exec"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, fi := range fis {
		n := fi.Name()
		if n[0] == '.' || !fi.IsDir() {
			continue
		}
		if notify.Exec[fi.Name()], err = cfgDirReadFromTo(src, "notify", "exec", n); err != nil {
			return nil, err
		}
	}
	if notify.File != nil || notify.Freq != nil || len(notify.Exec) > 0 {
		cfg.Notify = &notify
	}

	if _, err = ioutil.ReadDir(filepath.Join(src, "self")); err == nil {
		self := NodeOurJSON{}
		if self.Id, err = cfgDirLoadMust(src, "self", "id"); err != nil {
			return nil, err
		}
		if self.ExchPub, err = cfgDirLoadMust(src, "self", "exchpub"); err != nil {
			return nil, err
		}
		if self.ExchPrv, err = cfgDirLoadMust(src, "self", "exchprv"); err != nil {
			return nil, err
		}
		if self.SignPub, err = cfgDirLoadMust(src, "self", "signpub"); err != nil {
			return nil, err
		}
		if self.SignPrv, err = cfgDirLoadMust(src, "self", "signprv"); err != nil {
			return nil, err
		}
		if self.NoisePub, err = cfgDirLoadMust(src, "self", "noisepub"); err != nil {
			return nil, err
		}
		if self.NoisePrv, err = cfgDirLoadMust(src, "self", "noiseprv"); err != nil {
			return nil, err
		}
		cfg.Self = &self
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	cfg.Neigh = make(map[string]NodeJSON)
	fis, err = ioutil.ReadDir(filepath.Join(src, "neigh"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, fi := range fis {
		n := fi.Name()
		if n[0] == '.' {
			continue
		}
		node := NodeJSON{}
		if node.Id, err = cfgDirLoadMust(src, "neigh", n, "id"); err != nil {
			return nil, err
		}
		if node.ExchPub, err = cfgDirLoadMust(src, "neigh", n, "exchpub"); err != nil {
			return nil, err
		}
		if node.SignPub, err = cfgDirLoadMust(src, "neigh", n, "signpub"); err != nil {
			return nil, err
		}
		if node.NoisePub, err = cfgDirLoadOpt(src, "neigh", n, "noisepub"); err != nil {
			return nil, err
		}
		if node.Incoming, err = cfgDirLoadOpt(src, "neigh", n, "incoming"); err != nil {
			return nil, err
		}

		node.Exec = make(map[string][]string)
		fis2, err := ioutil.ReadDir(filepath.Join(src, "neigh", n, "exec"))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, fi2 := range fis2 {
			n2 := fi2.Name()
			if n2[0] == '.' {
				continue
			}
			s, err := cfgDirLoadMust(src, "neigh", n, "exec", n2)
			if err != nil {
				return nil, err
			}
			node.Exec[n2] = strings.Split(s, "\n")
		}

		if cfgDirExists(src, "neigh", n, "freq") {
			node.Freq = &NodeFreqJSON{}
			if node.Freq.Path, err = cfgDirLoadOpt(src, "neigh", n, "freq", "path"); err != nil {
				return nil, err
			}

			i64, err := cfgDirLoadIntOpt(src, "neigh", n, "freq", "chunked")
			if err != nil {
				return nil, err
			}
			if i64 != nil {
				i := uint64(*i64)
				node.Freq.Chunked = &i
			}

			i64, err = cfgDirLoadIntOpt(src, "neigh", n, "freq", "minsize")
			if err != nil {
				return nil, err
			}
			if i64 != nil {
				i := uint64(*i64)
				node.Freq.MinSize = &i
			}

			i64, err = cfgDirLoadIntOpt(src, "neigh", n, "freq", "maxsize")
			if err != nil {
				return nil, err
			}
			if i64 != nil {
				i := uint64(*i64)
				node.Freq.MaxSize = &i
			}
		}

		via, err := cfgDirLoadOpt(src, "neigh", n, "via")
		if err != nil {
			return nil, err
		}
		if via != nil {
			node.Via = strings.Split(*via, "\n")
		}

		node.Addrs = make(map[string]string)
		fis2, err = ioutil.ReadDir(filepath.Join(src, "neigh", n, "addrs"))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, fi2 := range fis2 {
			n2 := fi2.Name()
			if n2[0] == '.' {
				continue
			}
			if node.Addrs[n2], err = cfgDirLoadMust(src, "neigh", n, "addrs", n2); err != nil {
				return nil, err
			}
		}

		i64, err := cfgDirLoadIntOpt(src, "neigh", n, "rxrate")
		if err != nil {
			return nil, err
		}
		if i64 != nil {
			i := int(*i64)
			node.RxRate = &i
		}

		i64, err = cfgDirLoadIntOpt(src, "neigh", n, "txrate")
		if err != nil {
			return nil, err
		}
		if i64 != nil {
			i := int(*i64)
			node.TxRate = &i
		}

		i64, err = cfgDirLoadIntOpt(src, "neigh", n, "onlinedeadline")
		if err != nil {
			return nil, err
		}
		if i64 != nil {
			i := uint(*i64)
			node.OnlineDeadline = &i
		}

		i64, err = cfgDirLoadIntOpt(src, "neigh", n, "maxonlinetime")
		if err != nil {
			return nil, err
		}
		if i64 != nil {
			i := uint(*i64)
			node.MaxOnlineTime = &i
		}

		fis2, err = ioutil.ReadDir(filepath.Join(src, "neigh", n, "calls"))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		callsIdx := make([]int, 0, len(fis2))
		for _, fi2 := range fis2 {
			n2 := fi2.Name()
			if !fi2.IsDir() {
				continue
			}
			i, err := strconv.Atoi(n2)
			if err != nil {
				continue
			}
			callsIdx = append(callsIdx, i)
		}
		sort.Ints(callsIdx)
		for _, i := range callsIdx {
			call := CallJSON{}
			is := strconv.Itoa(i)
			if call.Cron, err = cfgDirLoadMust(
				src, "neigh", n, "calls", is, "cron",
			); err != nil {
				return nil, err
			}
			if call.Nice, err = cfgDirLoadOpt(
				src, "neigh", n, "calls", is, "nice",
			); err != nil {
				return nil, err
			}
			if call.Xx, err = cfgDirLoadOpt(
				src, "neigh", n, "calls", is, "xx",
			); err != nil {
				return nil, err
			}

			i64, err = cfgDirLoadIntOpt(src, "neigh", n, "calls", is, "rxrate")
			if err != nil {
				return nil, err
			}
			if i64 != nil {
				i := int(*i64)
				call.RxRate = &i
			}

			i64, err = cfgDirLoadIntOpt(src, "neigh", n, "calls", is, "txrate")
			if err != nil {
				return nil, err
			}
			if i64 != nil {
				i := int(*i64)
				call.TxRate = &i
			}

			if call.Addr, err = cfgDirLoadOpt(
				src, "neigh", n, "calls", is, "addr",
			); err != nil {
				return nil, err
			}

			i64, err = cfgDirLoadIntOpt(src, "neigh", n, "calls", is, "onlinedeadline")
			if err != nil {
				return nil, err
			}
			if i64 != nil {
				i := uint(*i64)
				call.OnlineDeadline = &i
			}

			i64, err = cfgDirLoadIntOpt(src, "neigh", n, "calls", is, "maxonlinetime")
			if err != nil {
				return nil, err
			}
			if i64 != nil {
				i := uint(*i64)
				call.MaxOnlineTime = &i
			}

			if cfgDirExists(src, "neigh", n, "calls", is, "when-tx-exists") {
				call.WhenTxExists = true
			}
			if cfgDirExists(src, "neigh", n, "calls", is, "nock") {
				call.NoCK = true
			}
			if cfgDirExists(src, "neigh", n, "calls", is, "mcd-ignore") {
				call.MCDIgnore = true
			}
			if cfgDirExists(src, "neigh", n, "calls", is, "autotoss") {
				call.AutoToss = true
			}
			if cfgDirExists(src, "neigh", n, "calls", is, "autotoss-doseen") {
				call.AutoTossDoSeen = true
			}
			if cfgDirExists(src, "neigh", n, "calls", is, "autotoss-nofile") {
				call.AutoTossNoFile = true
			}
			if cfgDirExists(src, "neigh", n, "calls", is, "autotoss-nofreq") {
				call.AutoTossNoFreq = true
			}
			if cfgDirExists(src, "neigh", n, "calls", is, "autotoss-noexec") {
				call.AutoTossNoExec = true
			}
			if cfgDirExists(src, "neigh", n, "calls", is, "autotoss-notrns") {
				call.AutoTossNoTrns = true
			}
			if cfgDirExists(src, "neigh", n, "calls", is, "autotoss-noarea") {
				call.AutoTossNoArea = true
			}
			node.Calls = append(node.Calls, call)
		}
		cfg.Neigh[n] = node
	}

	cfg.Areas = make(map[string]AreaJSON)
	fis, err = ioutil.ReadDir(filepath.Join(src, "areas"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, fi := range fis {
		n := fi.Name()
		if n[0] == '.' {
			continue
		}
		area := AreaJSON{}
		if area.Id, err = cfgDirLoadMust(src, "areas", n, "id"); err != nil {
			return nil, err
		}
		if area.Pub, err = cfgDirLoadOpt(src, "areas", n, "pub"); err != nil {
			return nil, err
		}
		if area.Prv, err = cfgDirLoadOpt(src, "areas", n, "prv"); err != nil {
			return nil, err
		}

		subs, err := cfgDirLoadOpt(src, "areas", n, "subs")
		if err != nil {
			return nil, err
		}
		if subs != nil {
			area.Subs = strings.Split(*subs, "\n")
		}

		area.Exec = make(map[string][]string)
		fis2, err := ioutil.ReadDir(filepath.Join(src, "areas", n, "exec"))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, fi2 := range fis2 {
			n2 := fi2.Name()
			if n2[0] == '.' {
				continue
			}
			s, err := cfgDirLoadMust(src, "areas", n, "exec", n2)
			if err != nil {
				return nil, err
			}
			area.Exec[n2] = strings.Split(s, "\n")
		}

		if area.Incoming, err = cfgDirLoadOpt(src, "areas", n, "incoming"); err != nil {
			return nil, err
		}

		if cfgDirExists(src, "areas", n, "allow-unknown") {
			area.AllowUnknown = true
		}
		cfg.Areas[n] = area
	}

	fis, err = ioutil.ReadDir(filepath.Join(src, "yggdrasil-aliases"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(fis) > 0 {
		cfg.YggdrasilAliases = make(map[string]string, len(fis))
	}
	for _, fi := range fis {
		n := fi.Name()
		if n[0] == '.' {
			continue
		}
		b, err := ioutil.ReadFile(filepath.Join(src, "yggdrasil-aliases", fi.Name()))
		if err != nil {
			return nil, err
		}
		cfg.YggdrasilAliases[n] = strings.TrimSuffix(string(b), "\n")
	}

	return &cfg, nil
}
