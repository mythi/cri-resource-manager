#include <uapi/linux/bpf.h>
#include <asm/page_types.h>
#include <asm/fpu/types.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef KERNEL_VERSION
    #define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#define BUF_SIZE_MAP_NS 256

typedef struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int pinning;
	char namespace[BUF_SIZE_MAP_NS];
} bpf_map_def;

static int (*bpf_probe_read)(void *dst, u64 size, const void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read;

static u64 (*bpf_get_current_cgroup_id)(void) = (void *)
	BPF_FUNC_get_current_cgroup_id;

static u64 (*bpf_ktime_get_ns)(void) = (void *)
	BPF_FUNC_ktime_get_ns;

static int (*bpf_map_update_elem)(void *map, void *key, void *value,
				  u64 flags) = (void *)BPF_FUNC_map_update_elem;

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)
	BPF_FUNC_map_lookup_elem;

struct bpf_map_def
	SEC("maps/avx_context_switch_count") avx_context_switch_count_hash = {
		.type = BPF_MAP_TYPE_HASH,
		.key_size = sizeof(u64),
		.value_size = sizeof(u32),
		.max_entries = 1024,
	};

struct bpf_map_def
	SEC("maps/avx_timestamp") avx_timestamp_hash = {
		.type = BPF_MAP_TYPE_HASH,
		.key_size = sizeof(u64),
		.value_size = sizeof(u32),
		.max_entries = 1024,
	};

struct bpf_map_def
	SEC("maps/last_update_ns") last_update_ns_hash = {
		.type = BPF_MAP_TYPE_HASH,
		.key_size = sizeof(u64),
		.value_size = sizeof(u64),
		.max_entries = 1024,
	};

struct bpf_map_def SEC("maps/cpu") cpu_hash = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(u32),
	.max_entries = 128,
};

struct x86_fpu_args {
	u64 pad;
	struct fpu *fpu;
	bool load_fpu;
	u64 xfeatures;
	u64 xcomp_bv;
};

SEC("tracepoint/x86_fpu/x86_fpu_regs_deactivated")
int tracepoint__x86_fpu_regs_deactivated(struct x86_fpu_args *args)
{
	u32 *counter;
	u32 ts;
	bpf_probe_read(&ts, sizeof(u32), (void *)&args->fpu->avx512_timestamp);

	if (ts == 0) {
		return 0;
	}

	u64 cgroup_id = bpf_get_current_cgroup_id();

	u32 ts_prev;
	u32 *tsp;
	tsp = bpf_map_lookup_elem(&avx_timestamp_hash, &cgroup_id);

	ts_prev = tsp ? *tsp : 0;

	if (ts == ts_prev) {
		return 0;
	}
	bpf_map_update_elem(&avx_timestamp_hash, &cgroup_id, &ts, BPF_ANY);

	unsigned int last_cpu;
	bpf_probe_read(&last_cpu, sizeof(last_cpu),
		       (void *)&args->fpu->last_cpu);

	u32 count = 1;
	counter = bpf_map_lookup_elem(&cpu_hash, &last_cpu);
	if (counter) {
		__sync_fetch_and_add(counter, 1);
	} else {
		bpf_map_update_elem(&cpu_hash, &last_cpu, &count, BPF_ANY);
	}

	counter = bpf_map_lookup_elem(&avx_context_switch_count_hash, &cgroup_id);
	if (counter) {
		__sync_fetch_and_add(counter, 1);
	} else {
		bpf_map_update_elem(&avx_context_switch_count_hash, &cgroup_id,
				    &count, BPF_ANY);
	}

	u64 last = bpf_ktime_get_ns();
	bpf_map_update_elem(&last_update_ns_hash, &cgroup_id, &last, BPF_ANY);

	return 0;
}

char _license[] SEC("license") = "GPL";

/*
Notes about Linux version:
   * We don't check LINUX_VERSION_CODE build time. It's user's responsibility to provide new enough headers.
   * Build failures may happen due to too old kernel headers (currently, Linux >= 5.1 headers are needed).
   * Our dependency to Kernel ABI is x86_fpu tracepoint parameters and struct fpu.
   * The host kernel needs to run Linux >= 5.2 and the version is checked upon eBPF loading.
   * We build the minimum supported version in SEC("version") section.
   * Max supported version is not checked but the check may be added later.
*/
unsigned int _version SEC("version") = KERNEL_VERSION(5, 2, 0);
