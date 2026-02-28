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
	// 692e1f5ab85105fbf485e9b82bdc775e55f7b22a8ade906d55dd893ab049f5d4
}

func Example_keyed() {
	h := digest.NewKeyed("com.example.mac", []byte("a secret key"))
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// d34cc74c69ee2a271e01fd9abecce6b0
}
