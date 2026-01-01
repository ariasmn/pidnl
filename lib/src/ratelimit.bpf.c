// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Rate limits in bytes per second
#define UPLOAD_LIMIT_BPS 10485760
#define DOWNLOAD_LIMIT_BPS 20971520

// Direction constants
#define DIRECTION_EGRESS 0   // Upload traffic (leaving the system)
#define DIRECTION_INGRESS 1  // Download traffic (entering the system)

// Rate limit state per direction
struct rate_limit_state {
    __u64 tokens;
    __u64 last_update_ns;
};

// Map to store rate limit state per direction (DIRECTION_EGRESS=0, DIRECTION_INGRESS=1)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct rate_limit_state);
} rate_state SEC(".maps");

// Token bucket rate limiting
// Returns: 1 = allow, 0 = drop
static __always_inline int rate_limit(__u32 direction, __u64 limit_bps, __u32 packet_size) {
    struct rate_limit_state *state;
    __u64 now = bpf_ktime_get_ns();
    __u64 tokens_to_add;
    __u64 elapsed_ns;

    state = bpf_map_lookup_elem(&rate_state, &direction);
    if (!state)
    {
        return 1;
    }

    // Calculate tokens to add based on elapsed time
    elapsed_ns = now - state->last_update_ns;
    tokens_to_add = (elapsed_ns / 1000000) * limit_bps / 1000;

    state->tokens += tokens_to_add;
    state->last_update_ns = now;

    // Cap tokens at 2x the rate limit (burst allowance)
    __u64 max_tokens = limit_bps * 2;
    if (state->tokens > max_tokens)
    {
        state->tokens = max_tokens;
    }

    // Check if we have enough tokens
    if (state->tokens >= packet_size) {
        state->tokens -= packet_size;
        return 1;
    }

    return 0;
}

SEC("cgroup/skb")
int egress_rate_limit(struct __sk_buff *skb) {
    // Direction 0 = egress (upload)
    return rate_limit(DIRECTION_EGRESS, UPLOAD_LIMIT_BPS, skb->len);
}

SEC("cgroup/skb")
int ingress_rate_limit(struct __sk_buff *skb) {
    // Direction 1 = ingress (download)
    return rate_limit(DIRECTION_INGRESS, DOWNLOAD_LIMIT_BPS, skb->len);
}

char _license[] SEC("license") = "GPL";
