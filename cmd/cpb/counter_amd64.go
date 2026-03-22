//go:build amd64 && !purego

package main

//go:noescape
func rdtsc() uint64

func readCounter() uint64            { return rdtsc() }
func counterScale(_ float64) float64 { return 1.0 }
