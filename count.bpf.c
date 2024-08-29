#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

// 0 - userspace faults
// 1 - kernelspace faults
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, __u64);
    __uint(max_entries, 2);
} faults SEC(".maps");

SEC("tracepoint/exceptions/page_fault_user")
int count_user(void *ctx) {
    int idx = 0;
    __u64 *count = bpf_map_lookup_elem(&faults, &idx);

    if (count) {
        __atomic_fetch_add(count, 1, __ATOMIC_RELAXED);
    }

    return 0;
}

SEC("tracepoint/exceptions/page_fault_kernel")
int count_kernel(void *ctx) {
    int idx = 1;
    __u64 *count = bpf_map_lookup_elem(&faults, &idx);

    if (count) {
        __atomic_fetch_add(count, 1, __ATOMIC_RELAXED);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
