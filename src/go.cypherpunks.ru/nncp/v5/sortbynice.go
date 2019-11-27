package nncp

type ByNice []*SPInfo

func (a ByNice) Len() int {
	return len(a)
}

func (a ByNice) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a ByNice) Less(i, j int) bool {
	return a[i].Nice < a[j].Nice
}
