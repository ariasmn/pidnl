// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

// Direction constants (used by both rate_limits and rate_state maps)
#define DIRECTION_UPLOAD 0   // Upload traffic (egress, leaving the system)
#define DIRECTION_DOWNLOAD 1 // Download traffic (ingress, entering the system)

// Rate limit state per direction (for token bucket)
struct rate_limit_state {
    __u64 tokens;
    __u64 last_update_ns;
};

// Map to store rate limit state per direction
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct rate_limit_state);
} rate_state SEC(".maps");

// Map to store rate limits in bytes per second (read from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} rate_limits SEC(".maps");

// Token bucket rate limiting
// TODO: This drops requests instead of delaying them.
// We need to revisit this since it's also not super reliable, but enough to
// work on all the logic and later change the algorithm.
// Returns: 1 = allow, 0 = drop
static __always_inline int
apply_rate_limit(__u32 direction, __u64 limit_bps, __u32 packet_size) {
    struct rate_limit_state *state;
    __u64 now = bpf_ktime_get_ns();
    __u64 tokens_to_add;
    __u64 elapsed_ns;

    state = bpf_map_lookup_elem(&rate_state, &direction);
    if (!state) {
        return 1;
    }

    // Calculate tokens to add based on elapsed time
    elapsed_ns = now - state->last_update_ns;
    tokens_to_add = (limit_bps / 1000000) * (elapsed_ns / 1000);

    state->tokens += tokens_to_add;
    state->last_update_ns = now;

    // Cap tokens at 2x the rate limit (burst allowance)
    __u64 max_tokens = limit_bps * 2;
    if (state->tokens > max_tokens) {
        state->tokens = max_tokens;
    }

    // Check if we have enough tokens
    if (state->tokens >= packet_size) {
        state->tokens -= packet_size;
        return 1;
    }

    return 0;
}

SEC("cgroup/skb") int egress_rate_limit(struct __sk_buff *skb) {
    __u32 key = DIRECTION_UPLOAD;
    __u64 *limit = bpf_map_lookup_elem(&rate_limits, &key);
    if (!limit) {
        return 1;
    }
    return apply_rate_limit(DIRECTION_UPLOAD, *limit, skb->len);
}

SEC("cgroup/skb") int ingress_rate_limit(struct __sk_buff *skb) {
    __u32 key = DIRECTION_DOWNLOAD;
    __u64 *limit = bpf_map_lookup_elem(&rate_limits, &key);
    if (!limit) {
        return 1;
    }
    return apply_rate_limit(DIRECTION_DOWNLOAD, *limit, skb->len);
}

char _license[] SEC("license") = "GPL";
