package digest_test

import (
	"fmt"
	"io"

	"github.com/codahale/thyrse/schemes/basic/digest"
)

func Example_unkeyed() {
	h := digest.New("com.example.digest")
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// c2f7d6685e794b09902f04b7230f1b62a98b95aa33b812dae52ce2066527bbb4
}

func Example_keyed() {
	h := digest.NewKeyed("com.example.mac", []byte("a secret key"))
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// a95d0c0f6453bacbe98aa95f24416cac
}
