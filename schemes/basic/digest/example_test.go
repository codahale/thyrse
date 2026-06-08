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
	// 34d9923f417eb768ac77fb5c21792bdbc4ffd80dd23e7f622f2cbb335d26b762
}

func Example_keyed() {
	h := digest.NewKeyed("com.example.mac", []byte("a secret key"))
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// 60fefc8409b4e23ac477a76b6bfc6497
}
