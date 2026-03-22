//go:build arm64 && !purego

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

//go:noescape
func cntvct() uint64

//go:noescape
func cntfrq() uint64

func readCounter() uint64 { return cntvct() }

func counterScale(freqGHz float64) float64 {
	cf := float64(cntfrq())
	if cf == 0 {
		fmt.Fprintln(os.Stderr, "error: CNTFRQ_EL0 returned 0")
		os.Exit(1)
	}

	cpuHz := freqGHz * 1e9
	if cpuHz == 0 {
		cpuHz = detectCPUFreq()
	}
	if cpuHz == 0 {
		fmt.Fprintln(os.Stderr, "error: could not detect CPU frequency; specify --freq in GHz (e.g. --freq=3.5)")
		os.Exit(1)
	}

	return cpuHz / cf
}

func detectCPUFreq() float64 {
	switch runtime.GOOS {
	case "darwin":
		return detectDarwin()
	case "linux":
		return detectLinux()
	}
	return 0
}

func detectDarwin() float64 {
	// hw.cpufrequency_max reports Hz on macOS.
	out, err := exec.Command("sysctl", "-n", "hw.cpufrequency_max").Output()
	if err == nil {
		if hz, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); err == nil && hz > 0 {
			return hz
		}
	}
	return 0
}

func detectLinux() float64 {
	// cpuinfo_max_freq reports kHz on Linux.
	data, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
	if err == nil {
		if khz, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil && khz > 0 {
			return khz * 1e3
		}
	}
	return 0
}
