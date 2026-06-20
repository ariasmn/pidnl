// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

// Direction constants (used by both rate_limits and rate_state maps)
#define DIRECTION_UPLOAD 0   // Upload traffic (egress, leaving the system)
#define DIRECTION_DOWNLOAD 1 // Download traffic (ingress, entering the system)

// Rate limit state per direction (for token bucket)
struct rate_limit_state {
    struct bpf_spin_lock lock; // must be first field
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

// Map to store rate limits in kbps (read from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} rate_limits SEC(".maps");

// Token bucket rate limiting
// TODO: This drops requests instead of delaying them.
// We need to revisit this since it's also not super reliable, but enough to
// work on all the logic and later change the algorithm.
// Returns: 1 = allow, 0 = drop
static __always_inline int apply_rate_limit(__u32 direction, __u32 limit_kbps, __u32 packet_size) {
    struct rate_limit_state *state;
    __u64 limit_bps = (__u64)limit_kbps * 1000 / 8;
    __u64 now = bpf_ktime_get_ns();

    state = bpf_map_lookup_elem(&rate_state, &direction);
    if (!state) {
        return 1;
    }

    bpf_spin_lock(&state->lock);

    // Calculate tokens to add based on elapsed time.
    // Convert to microseconds first to avoid overflow at high rates,
    // then cap at 1s to limit burst accumulation.
    __u64 elapsed_us = (now - state->last_update_ns) / 1000;
    if (elapsed_us > 1000000ULL) {
        elapsed_us = 1000000ULL;
    }
    __u64 tokens_to_add = (limit_bps * elapsed_us) / 1000000ULL;

    state->tokens += tokens_to_add;
    state->last_update_ns = now;

    // Cap tokens at 2x the rate limit (burst allowance)
    __u64 max_tokens = limit_bps * 2;
    if (state->tokens > max_tokens) {
        state->tokens = max_tokens;
    }

    // Check if we have enough tokens
    int ret = 0;
    if (state->tokens >= packet_size) {
        state->tokens -= packet_size;
        ret = 1;
    }

    bpf_spin_unlock(&state->lock);
    return ret;
}

SEC("cgroup/skb")
int egress_rl(struct __sk_buff *skb) {
    __u32 key = DIRECTION_UPLOAD;
    __u32 *limit = bpf_map_lookup_elem(&rate_limits, &key);
    if (!limit) {
        return 1;
    }
    return apply_rate_limit(DIRECTION_UPLOAD, *limit, skb->len);
}

SEC("cgroup/skb")
int ingress_rl(struct __sk_buff *skb) {
    __u32 key = DIRECTION_DOWNLOAD;
    __u32 *limit = bpf_map_lookup_elem(&rate_limits, &key);
    if (!limit) {
        return 1;
    }
    return apply_rate_limit(DIRECTION_DOWNLOAD, *limit, skb->len);
}

char _license[] SEC("license") = "GPL";
