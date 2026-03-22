//go:build (!amd64 && !arm64) || purego

package main

func readCounter() uint64            { panic("cycle counter not supported on this platform") }
func counterScale(_ float64) float64 { panic("cycle counter not supported on this platform") }
