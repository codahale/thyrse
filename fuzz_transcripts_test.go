package thyrse_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/internal/testdata"
	fuzz "github.com/trailofbits/go-fuzz-utils"
)

// FuzzProtocolDivergence generates a random transcript of operations and performs them in on two separate protocol
// objects in parallel, checking to see that all outputs are the same.
func FuzzProtocolDivergence(f *testing.F) {
	drbg := testdata.New("thyrse divergence")
	for range 10 {
		f.Add(drbg.Data(1024))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := fuzz.NewTypeProvider(data)
		if err != nil {
			t.Skip(err)
		}

		opCount, err := tp.GetUint16()
		if err != nil {
			t.Skip(err)
		}

		p1 := thyrse.New("divergence")
		p2 := thyrse.New("divergence")

		for range opCount % 50 {
			opTypeRaw, err := tp.GetByte()
			if err != nil {
				t.Skip(err)
			}

			label, err := tp.GetString()
			if err != nil {
				t.Skip(err)
			}

			const opTypeCount = 6 // Mix, MixDigest, Derive, Ratchet, Mask, Seal
			switch opType := opTypeRaw % opTypeCount; opType {
			case 0: // Mix
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				p1.Mix(label, input)
				p2.Mix(label, input)
			case 1: // MixDigest
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				_ = p1.MixDigest(label, bytes.NewReader(input))
				_ = p2.MixDigest(label, bytes.NewReader(input))
			case 2: // Derive
				n, err := tp.GetUint16()
				if err != nil || n == 0 {
					t.Skip(err)
				}

				res1, res2 := p1.Derive(label, nil, int(n)), p2.Derive(label, nil, int(n))
				if !bytes.Equal(res1, res2) {
					t.Fatalf("Divergent Derive outputs: %x != %x", res1, res2)
				}
			case 3: // Ratchet
				p1.Ratchet(label)
				p2.Ratchet(label)
			case 4: // Mask
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				res1, res2 := p1.Mask(label, nil, input), p2.Mask(label, nil, input)
				if !bytes.Equal(res1, res2) {
					t.Fatalf("Divergent Mask outputs: %x != %x", res1, res2)
				}
			case 5: // Seal
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				res1, res2 := p1.Seal(label, nil, input), p2.Seal(label, nil, input)
				if !bytes.Equal(res1, res2) {
					t.Fatalf("Divergent Seal outputs: %x != %x", res1, res2)
				}
			default:
				panic(fmt.Sprintf("unknown operation type: %v", opType))
			}
		}

		if p1.Equal(p2) != 1 {
			t.Fatal("divergent final states")
		}
	})
}

// FuzzProtocolReversibility generates a transcript of reversible operations (Mix, Derive, Mask, and Seal) and
// performs them on a protocol, recording the outputs. It then runs the transcript's duals (Mix, Derive, Unmask, and
// Open) on another protocol object, ensuring the outputs are the same as the inputs.
func FuzzProtocolReversibility(f *testing.F) {
	drbg := testdata.New("thyrse reversibility")
	for range 10 {
		f.Add(drbg.Data(1024))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := fuzz.NewTypeProvider(data)
		if err != nil {
			t.Skip(err)
		}

		opCount, err := tp.GetUint16()
		if err != nil {
			t.Skip(err)
		}

		p1 := thyrse.New("reversibility")

		var operations []operation
		for range opCount % 50 {
			opTypeRaw, err := tp.GetByte()
			if err != nil {
				t.Skip(err)
			}

			label, err := tp.GetString()
			if err != nil {
				t.Skip(err)
			}

			const opTypeCount = 6 // Mix, MixDigest, Derive, Ratchet, Mask, Seal
			switch opType := opTypeRaw % opTypeCount; opType {
			case 0: // Mix
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				p1.Mix(label, input)

				operations = append(operations, operation{
					opType: 0,
					label:  label,
					input:  input,
				})
			case 1: // MixDigest
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				_ = p1.MixDigest(label, bytes.NewReader(input))

				operations = append(operations, operation{
					opType: 1,
					label:  label,
					input:  input,
				})
			case 2: // Derive
				n, err := tp.GetUint16()
				if err != nil || n == 0 {
					t.Skip(err)
				}

				output := p1.Derive(label, nil, max(int(n), 1))

				operations = append(operations, operation{
					opType: 2,
					label:  label,
					n:      max(int(n), 1),
					output: output,
				})
			case 3: // Ratchet
				p1.Ratchet(label)

				operations = append(operations, operation{
					opType: 3,
					label:  label,
				})
			case 4: // Mask
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				output := p1.Mask(label, nil, input)

				operations = append(operations, operation{
					opType: 4,
					label:  label,
					input:  input,
					output: output,
				})
			case 5: // Seal
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				output := p1.Seal(label, nil, input)

				operations = append(operations, operation{
					opType: 5,
					label:  label,
					input:  input,
					output: output,
				})
			default:
				panic(fmt.Sprintf("unknown operation type: %v", opType))
			}
		}

		p2 := thyrse.New("reversibility")
		for _, op := range operations {
			switch op.opType {
			case 0: // Mix
				p2.Mix(op.label, op.input)
			case 1: // MixDigest
				_ = p2.MixDigest(op.label, bytes.NewReader(op.input))
			case 2: // Derive
				output := p2.Derive(op.label, nil, op.n)
				if !bytes.Equal(output, op.output) {
					t.Fatalf("Divergent Derive outputs: %x != %x", output, op.output)
				}
			case 3: // Ratchet
				p2.Ratchet(op.label)
			case 4: // Unmask
				plaintext := p2.Unmask(op.label, nil, op.output)
				if !bytes.Equal(plaintext, op.input) {
					t.Fatalf("Invalid Unmask output: %x != %x", plaintext, op.input)
				}
			case 5: // Open
				plaintext, err := p2.Open(op.label, nil, op.output)
				if err != nil {
					t.Fatalf("Invalid Open operation: %v", err)
				}
				if !bytes.Equal(plaintext, op.input) {
					t.Fatalf("Invalid Open output: %x != %x", plaintext, op.input)
				}
			default:
				panic(fmt.Sprintf("unknown operation type: %v", op.opType))
			}
		}

		if p1.Equal(p2) != 1 {
			t.Fatal("divergent final states")
		}
	})
}

type operation struct {
	opType        byte
	label         string
	input, output []byte
	n             int
}
