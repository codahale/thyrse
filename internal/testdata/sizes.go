package testdata

type Size struct {
	Name string
	N    int
}

var Sizes []Size = []Size{
	{"1B", 1},
	{"64B", 64},
	{"8KiB", 8 * 1024},
	{"32KiB", 32 * 1024},
	{"64KiB", 64 * 1024},
	{"1MiB", 1024 * 1024},
	{"16MiB", 16 * 1024 * 1024},
}
