package avx

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/intel/cri-resource-manager/pkg/cgroups"
	logger "github.com/intel/cri-resource-manager/pkg/log"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

const (
	// LastCPUName is the Prometheuse Gauge name for last CPU with AVX512 instructions.
	LastCPUName = "last_cpu_avx_task_switches"
	// AVXSwitchCountName is the Prometheuse Gauge name for AVX switch count per cgroup.
	AVXSwitchCountName = "avx_switch_count_per_cgroup"
	// AllSwitchCountName is the Prometheuse Gauge name for all switch count per cgroup.
	AllSwitchCountName = "all_switch_count_per_cgroup"
	// LastUpdateNs is the Prometheuse Gauge name for per cgroup AVX512 activity timestamp.
	LastUpdateNs = "last_update_ns"
	// Path to kernel tracepoints
	kernelTracepointPath = "/sys/kernel/debug/tracing/events"
)

// Prometheus Metric descriptor indices and descriptor table
const (
	lastCPUDesc = iota
	avxSwitchCountDesc
	allSwitchCountDesc
	lastUpdateNsDesc
	numDescriptors
)

var descriptors = [numDescriptors]*prometheus.Desc{
	lastCPUDesc: prometheus.NewDesc(
		LastCPUName,
		"Number of task switches on the CPU where AVX512 instructions were used.",
		[]string{
			"cpu_id",
		}, nil,
	),
	avxSwitchCountDesc: prometheus.NewDesc(
		AVXSwitchCountName,
		"Number of task switches where AVX512 instructions were used in a particular cgroup.",
		[]string{
			"cgroup",
			"cgroup_id",
		}, nil,
	),
	allSwitchCountDesc: prometheus.NewDesc(
		AllSwitchCountName,
		"Total number of task switches in a particular cgroup.",
		[]string{
			"cgroup",
		}, nil,
	),
	lastUpdateNsDesc: prometheus.NewDesc(
		"last_update_ns",
		"Time since last AVX512 activity in a particular cgroup.",
		[]string{
			"cgroup",
		}, nil,
	),
}

var (
	// our logger instance
	log = logger.NewLogger("avx")
)

type collector struct {
	root string
	ebpf *bpf.Collection
	pfd  int
}

func enablePerfTracepoint(fd int, tracepoint string) (int, error) {

	path := filepath.Join(kernelTracepointPath, tracepoint, "id")
	log.Debug("tracepoint: %s", path)

	id, err := ioutil.ReadFile(path)
	if err != nil {
		return -1, errors.Wrap(err, "unable read tracepoint ID")
	}
	tid, err := strconv.Atoi(strings.TrimSpace(string(id)))
	if err != nil {
		return -1, errors.New("unable to convert tracepoint ID")
	}

	log.Debug("tracepoint ID: %d", tid)
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      uint64(tid), // tracepoint id
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}
	pfd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, errors.Wrap(err, "unable open perf events")
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_ENABLE, 0); errno != 0 {
		return -1, errors.New("unable to set up perf events")
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(fd)); errno != 0 {
		return -1, errors.New("unable to attach bpf program to perf events")
	}

	return pfd, nil
}

// NewCollector creates new Prometheus collector for AVX metrics
func NewCollector() (prometheus.Collector, error) {

	// TODO: get rid of this
	// Increase `ulimit -l` limit to avoid BPF_PROG_LOAD error (runc #2167).
	memlockLimit := &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, memlockLimit)

	mapSpec := map[string]*bpf.MapSpec{
		"avx_timestamp": {
			Type:       bpf.Hash,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: 1024,
		},
		"avx_context_switch_count": {
			Type:       bpf.Hash,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: 1024,
		},
		"last_update_ns": {
			Type:       bpf.Hash,
			KeySize:    8,
			ValueSize:  8,
			MaxEntries: 1024,
		},
		"cpu_hash": {
			Type:       bpf.Hash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 128,
		},
	}
	var collectionMaps = make(map[string]*bpf.Map, len(mapSpec))

	for m, s := range mapSpec {
		newMap, err := bpf.NewMap(s)
		if err != nil {
			return nil, err
		}
		collectionMaps[m] = newMap
	}

	// based on: llvm-objdump -S -no-show-raw-insn libexec/avx512.o (built with -g)
	insns := asm.Instructions{
		// r1 has ctx
		asm.Mov.Reg(asm.R6, asm.R1),

		// r3 = *(u64 *)(r6 + 8)
		asm.LoadMem(asm.R3, asm.R6, 8, asm.DWord),
		asm.Add.Imm(asm.R3, 8),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.FnProbeRead.Call(),

		asm.LoadMem(asm.R1, asm.RFP, -4, asm.Word),

		// exit if avx512_timestamp is 0
		asm.JEq.Imm(asm.R1, 0, "exit"),

		asm.FnGetCurrentCgroupId.Call(),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),

		// did timestamp change?
		asm.LoadMapPtr(asm.R1, collectionMaps["avx_timestamp"].FD()),
		asm.FnMapLookupElem.Call(),
		asm.Mov.Imm(asm.R1, 0),
		asm.JEq.Imm(asm.R0, 0, "timestamp"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.LSh.Imm(asm.R1, 32).Sym("timestamp"),
		asm.RSh.Imm(asm.R1, 32),
		asm.LoadMem(asm.R2, asm.RFP, -4, asm.Word),
		asm.JEq.Reg(asm.R2, asm.R1, "exit"),

		// update timestamp
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -4),
		asm.LoadMapPtr(asm.R1, collectionMaps["avx_timestamp"].FD()),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),

		// last CPU
		asm.LoadMem(asm.R3, asm.R6, 8, asm.DWord),
		asm.Mov.Reg(asm.R6, asm.RFP),
		asm.Add.Imm(asm.R6, -20),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 4),
		asm.FnProbeRead.Call(),

		asm.Mov.Imm(asm.R7, 1),
		asm.StoreMem(asm.RFP, -24, asm.R7, asm.Word),
		asm.LoadMapPtr(asm.R1, collectionMaps["cpu_hash"].FD()),
		asm.Mov.Reg(asm.R2, asm.R6),
		asm.FnMapLookupElem.Call(),

		// update counter atomically
		asm.JEq.Imm(asm.R0, 0, "skip-atomic1"),
		asm.StoreXAdd(asm.R0, asm.R7, asm.Word),
		asm.Ja.Label("next-map"),

		asm.Mov.Reg(asm.R2, asm.RFP).Sym("skip-atomic1"),
		asm.Add.Imm(asm.R2, -20),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -24),
		asm.LoadMapPtr(asm.R1, collectionMaps["cpu_hash"].FD()),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),

		asm.Mov.Reg(asm.R2, asm.RFP).Sym("next-map"),
		asm.Add.Imm(asm.R2, -16),
		asm.LoadMapPtr(asm.R1, collectionMaps["avx_context_switch_count"].FD()),
		asm.FnMapLookupElem.Call(),

		// update counter atomically
		asm.JEq.Imm(asm.R0, 0, "skip-atomic2"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.Word),
		asm.Ja.Label("get-ns"),

		asm.Mov.Reg(asm.R2, asm.RFP).Sym("skip-atomic2"),
		asm.Add.Imm(asm.R2, -16),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -24),
		asm.LoadMapPtr(asm.R1, collectionMaps["avx_context_switch_count"].FD()),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),

		asm.FnKtimeGetNs.Call().Sym("get-ns"),
		asm.StoreMem(asm.RFP, -32, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -32),
		asm.LoadMapPtr(asm.R1, collectionMaps["last_update_ns"].FD()),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),

		// return value and exit
		asm.Mov.Imm(asm.R0, 0).Sym("exit"),
		asm.Return(),
	}

	prog, err := bpf.NewProgram(&bpf.ProgramSpec{
		Name:         "avx_collector",
		Type:         bpf.TracePoint,
		License:      "GPL",
		Instructions: insns,
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to create Program")
	}

	collection := &bpf.Collection{
		Programs: map[string]*bpf.Program{
			"avx_collector": prog,
		},
		Maps: collectionMaps,
	}

	fd, err := enablePerfTracepoint(prog.FD(), "x86_fpu/x86_fpu_regs_deactivated")
	if err != nil {
		return nil, errors.Wrap(err, "unable to enable perf tracepoint")
	}

	return &collector{
		root: cgroups.V2path,
		ebpf: collection,
		pfd:  fd,
	}, nil
}

// Describe implements prometheus.Collector interface
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range descriptors {
		ch <- d
	}
}

// TODO use bpf.NowNanoseconds() after https://github.com/iovisor/gobpf/pull/222
// nowNanoseconds returns a time that can be compared to bpf_ktime_get_ns()
func nowNanoseconds() uint64 {
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1 /* CLOCK_MONOTONIC */, uintptr(unsafe.Pointer(&ts)), 0)
	sec, nsec := ts.Unix()
	return 1000*1000*1000*uint64(sec) + uint64(nsec)
}

// Collect implements prometheus.Collector interface
func (c collector) Collect(ch chan<- prometheus.Metric) {
	var (
		wg  sync.WaitGroup
		key uint64
		val uint32
	)

	cgroupids := make(map[uint64]uint32)

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.collectLastCPUStats(ch)
	}()

	cg := cgroups.NewCgroupID(c.root)

	m := c.ebpf.Maps["avx_context_switch_count"]
	iter := m.Iterate()

	for iter.Next(&key, &val) {
		cgroupids[key] = val
		log.Debug("cgroupid %d => counter %d", key, val)
	}

	if iter.Err() != nil {
		log.Error("unable to iterate all elements of avx_context_switch_count: %+v", iter.Err())
	}

	for cgroupid, counter := range cgroupids {
		wg.Add(1)
		go func(cgroupid_ uint64, counter_ uint32) {
			var lastUpdate uint64

			defer wg.Done()

			path, err := cg.Find(cgroupid_)
			if err != nil {
				log.Error("failed to find cgroup by id: %v", err)
				return
			}

			ch <- prometheus.MustNewConstMetric(
				descriptors[avxSwitchCountDesc],
				prometheus.GaugeValue,
				float64(counter_),
				path,
				fmt.Sprintf("%d", cgroupid_))

			if err := c.ebpf.Maps["last_update_ns"].Lookup(uint64(cgroupid_), &lastUpdate); err != nil {
				log.Error("unable to find last update timestamp: %+v", err)
				return
			}

			ch <- prometheus.MustNewConstMetric(
				descriptors[lastUpdateNsDesc],
				prometheus.GaugeValue,
				float64(nowNanoseconds()-lastUpdate),
				path)

		}(cgroupid, counter)
	}

	// We need to wait so that the response channel doesn't get closed.
	wg.Wait()

	key = 0
	iter = m.Iterate()
	for iter.Next(&key, &val) {
		if err := m.Delete(key); err != nil {
			log.Error("%+v", err)
		}
	}
	if iter.Err() != nil {
		log.Error("unable to delete all elements of avx_context_switch_count: %+v", iter.Err())
	}
}

func (c collector) collectLastCPUStats(ch chan<- prometheus.Metric) {

	lastCPUs := make(map[uint32]uint32)
	var cpu uint32
	var counter uint32

	m := c.ebpf.Maps["cpu_hash"]
	iter := m.Iterate()
	for iter.Next(&cpu, &counter) {
		lastCPUs[cpu] = counter
		log.Debug("CPU%d = %d", cpu, counter)
	}

	if iter.Err() != nil {
		log.Error("unable to iterate all elements of last_cpu_avx_task_switches: %+v", iter.Err())
		return
	}

	for lastCPU, count := range lastCPUs {
		ch <- prometheus.MustNewConstMetric(
			descriptors[lastCPUDesc],
			prometheus.GaugeValue,
			float64(count),
			fmt.Sprintf("CPU%d", lastCPU))
	}
	cpu = 0
	iter = m.Iterate()
	for iter.Next(&cpu, &counter) {
		err := m.Delete(cpu)
		if err != nil {
			log.Error("%+v", err)
		}
	}
	if iter.Err() != nil {
		log.Error("unable to delete all elements of last_cpu_avx_task_switches: %+v", iter.Err())
	}
}
