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
	// e87dc46e5874ea98798f382d76931b2f63a4a2f65c59940a44d66819200bc908
}

func Example_keyed() {
	h := digest.NewKeyed("com.example.mac", []byte("a secret key"))
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// 8d4c7da43cf510e7972a19588e036820
}
