// Shared setup for the faiss libFuzzer harnesses.
#pragma once
#include <omp.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <faiss/index_io.h>

// The deserialization limits only exist since the index_read hardening commits; declare them weak so
// the harnesses also build at older commits (bug mining), where the call is simply skipped.
namespace faiss {
__attribute__((weak)) void set_deserialization_loop_limit(size_t value);
__attribute__((weak)) void set_deserialization_vector_byte_limit(size_t value);
} // namespace faiss

static inline void fuzz_faiss_init() {
    // One thread: deterministic and fast. State set here is process-wide but never changed by an input.
    omp_set_num_threads(1);
    // Bound allocations driven by sizes in the stream (memory exhaustion is not the target bug class).
    if (&faiss::set_deserialization_vector_byte_limit)
        faiss::set_deserialization_vector_byte_limit(size_t(64) << 20);
    if (&faiss::set_deserialization_loop_limit)
        faiss::set_deserialization_loop_limit(size_t(1) << 20);
}

// n floats taken cyclically from buf (zeros when empty). Any bit pattern, NaN and Inf included.
static inline std::vector<float> floats_from(const uint8_t* buf, size_t len, size_t n) {
    std::vector<float> v(n, 0.0f);
    if (len == 0) return v;
    size_t pos = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b[4];
        for (int j = 0; j < 4; j++) b[j] = buf[(pos++) % len];
        std::memcpy(&v[i], b, 4);
    }
    return v;
}
