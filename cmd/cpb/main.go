// Command cpb measures TW128 and AES-128-GCM performance in cycles per byte.
//
// On AMD64, it reads the RDTSC counter directly (reference cycles, no scaling).
// On ARM64, it reads CNTVCT_EL0 and scales to CPU cycles using CNTFRQ_EL0 and
// the CPU frequency (auto-detected or via --freq).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"slices"
	"time"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/internal/tw128"
)

type result struct {
	Alg   string  `json:"alg"`
	Op    string  `json:"op"`
	Size  string  `json:"size"`
	Bytes int     `json:"bytes"`
	CPB   float64 `json:"cpb"`
}

func main() {
	freq := flag.Float64("freq", 0, "CPU frequency in GHz (auto-detected if omitted)")
	nSamples := flag.Int("samples", 21, "number of measurement samples")
	target := flag.Duration("target", 100*time.Millisecond, "minimum duration per calibration run")
	format := flag.String("format", "table", "output format: table, csv, or json")
	flag.Parse()

	runtime.LockOSThread()

	scale := counterScale(*freq)

	key := make([]byte, tw128.KeySize)
	nonce := make([]byte, tw128.NonceSize)

	var results []result

	gcmKey := make([]byte, 16)
	gcmNonce := make([]byte, 12)

	for _, size := range testdata.Sizes {
		src := make([]byte, size.N)
		dst := make([]byte, size.N)

		// TW128 encrypt.
		encFn := func() {
			e := tw128.NewEncryptor(key, nonce, nil)
			e.XORKeyStream(dst, src)
			e.Finalize()
		}
		iters := calibrate(encFn, *target)
		results = append(results, result{
			Alg: "tw128", Op: "encrypt", Size: size.Name, Bytes: size.N,
			CPB: measure(encFn, iters, *nSamples, scale, size.N),
		})

		// TW128 decrypt.
		decFn := func() {
			d := tw128.NewDecryptor(key, nonce, nil)
			d.XORKeyStream(dst, src)
			d.Finalize()
		}
		iters = calibrate(decFn, *target)
		results = append(results, result{
			Alg: "tw128", Op: "decrypt", Size: size.Name, Bytes: size.N,
			CPB: measure(decFn, iters, *nSamples, scale, size.N),
		})

		// AES-128-GCM seal (key schedule included in measurement).
		gcmDst := make([]byte, 0, size.N+16)
		sealFn := func() {
			block, _ := aes.NewCipher(gcmKey)
			gcm, _ := cipher.NewGCM(block)
			gcmDst = gcm.Seal(gcmDst[:0], gcmNonce, src, nil)
		}
		iters = calibrate(sealFn, *target)
		results = append(results, result{
			Alg: "aes128gcm", Op: "seal", Size: size.Name, Bytes: size.N,
			CPB: measure(sealFn, iters, *nSamples, scale, size.N),
		})

		// AES-128-GCM open (key schedule included in measurement).
		block, _ := aes.NewCipher(gcmKey)
		gcm, _ := cipher.NewGCM(block)
		ct := gcm.Seal(nil, gcmNonce, src, nil)
		openDst := make([]byte, 0, size.N)
		openFn := func() {
			block, _ := aes.NewCipher(gcmKey)
			gcm, _ := cipher.NewGCM(block)
			openDst, _ = gcm.Open(openDst[:0], gcmNonce, ct, nil)
		}
		iters = calibrate(openFn, *target)
		results = append(results, result{
			Alg: "aes128gcm", Op: "open", Size: size.Name, Bytes: size.N,
			CPB: measure(openFn, iters, *nSamples, scale, size.N),
		})
	}

	switch *format {
	case "csv":
		outputCSV(results)
	case "json":
		outputJSON(results)
	default:
		outputTable(results, *freq)
	}
}

// calibrate finds the iteration count that fills at least target duration.
func calibrate(fn func(), target time.Duration) int {
	iters := 1
	for {
		start := time.Now()
		for range iters {
			fn()
		}
		if time.Since(start) >= target {
			return iters
		}
		iters *= 2
	}
}

// measure collects nSamples measurements and returns the median cycles per byte.
func measure(fn func(), iters, nSamples int, scale float64, bytes int) float64 {
	fn() // warm up

	samples := make([]float64, nSamples)
	for i := range nSamples {
		start := readCounter()
		for range iters {
			fn()
		}
		end := readCounter()
		ticksPerOp := float64(end-start) / float64(iters)
		samples[i] = ticksPerOp * scale / float64(bytes)
	}

	slices.Sort(samples)
	return samples[len(samples)/2]
}

func outputTable(results []result, freqGHz float64) {
	fmt.Printf("cycles/byte (%s/%s", runtime.GOOS, runtime.GOARCH)
	if freqGHz > 0 {
		fmt.Printf(", %.2f GHz", freqGHz)
	}
	fmt.Println(")")
	fmt.Println()

	// Collect ordered unique sizes and row keys.
	var sizes []string
	sizeSeen := make(map[string]bool)
	var rows []string
	rowSeen := make(map[string]bool)
	for _, r := range results {
		if !sizeSeen[r.Size] {
			sizes = append(sizes, r.Size)
			sizeSeen[r.Size] = true
		}
		key := r.Alg + " " + r.Op
		if !rowSeen[key] {
			rows = append(rows, key)
			rowSeen[key] = true
		}
	}

	cpb := make(map[string]float64)
	for _, r := range results {
		cpb[r.Alg+" "+r.Op+"/"+r.Size] = r.CPB
	}

	// Find the widest row label.
	labelW := 0
	for _, row := range rows {
		if len(row) > labelW {
			labelW = len(row)
		}
	}
	labelW += 2

	colW := 10
	fmt.Printf("%-*s", labelW, "")
	for _, s := range sizes {
		fmt.Printf("%*s", colW, s)
	}
	fmt.Println()

	for _, row := range rows {
		fmt.Printf("%-*s", labelW, row)
		for _, s := range sizes {
			v := cpb[row+"/"+s]
			if v >= 100 {
				fmt.Printf("%*.0f", colW, v)
			} else {
				fmt.Printf("%*.2f", colW, v)
			}
		}
		fmt.Println()
	}
}

func outputCSV(results []result) {
	w := csv.NewWriter(os.Stdout)
	_ = w.Write([]string{"alg", "operation", "size", "bytes", "cpb"})
	for _, r := range results {
		_ = w.Write([]string{r.Alg, r.Op, r.Size, fmt.Sprint(r.Bytes), fmt.Sprintf("%.2f", r.CPB)})
	}
	w.Flush()
}

func outputJSON(results []result) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
}
