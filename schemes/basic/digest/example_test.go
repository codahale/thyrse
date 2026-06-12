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
	// 2fcccc55dd22ed2aa131e004161003ddc47b4cbfe1e4eb584c617638a082ca83
}

func Example_keyed() {
	h := digest.NewKeyed("com.example.mac", []byte("a secret key"))
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// 5ee280f25aa7ed49833f7bb288b680df
}
