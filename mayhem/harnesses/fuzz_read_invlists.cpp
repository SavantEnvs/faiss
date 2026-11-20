// faiss::read_InvertedLists on an untrusted byte stream, then walk the lists it produced.
#include <memory>
#include <faiss/impl/FaissException.h>
#include <faiss/impl/io.h>
#include <faiss/index_io.h>
#include <faiss/invlists/BlockInvertedLists.h>
#include <faiss/invlists/InvertedLists.h>
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    fuzz_faiss_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // VectorIOReader owns an aligned copy (ZeroCopyIOReader would hand out views at arbitrary,
    // misaligned offsets of the fuzzer buffer, which is a harness artifact, not a faiss bug).
    faiss::VectorIOReader r;
    r.data.assign(data, data + size);
    std::unique_ptr<faiss::InvertedLists> il;
    try {
        il.reset(faiss::read_InvertedLists(&r, 0));
    } catch (const std::exception&) {
        return 0;
    }
    if (!il) return 0;
    try {
        volatile uint64_t sink = 0;
        // Only touch bytes faiss hands back, in the layout of the concrete list type: an
        // ArrayInvertedLists (and its Panorama subclass) stores list_size * code_size code bytes
        // per list, which read_InvertedLists validated with mul_no_overflow; a BlockInvertedLists
        // stores blocks and carries an input-chosen code_size that is not a per-entry stride, so
        // its codes are read through the buffer faiss allocated, never via n * code_size.
        auto* ail = dynamic_cast<faiss::ArrayInvertedLists*>(il.get());
        auto* bil = dynamic_cast<faiss::BlockInvertedLists*>(il.get());
        for (size_t l = 0; l < il->nlist && l < 64; l++) {
            size_t n = il->list_size(l);
            if (n == 0) continue;
            const faiss::idx_t* ids = il->get_ids(l);
            if (ids) sink += ids[n - 1];
            il->release_ids(l, ids);
            if (ail) {
                faiss::InvertedLists::ScopedCodes codes(il.get(), l);
                size_t list_bytes;
                if (codes.get() && il->code_size &&
                    !__builtin_mul_overflow(n, il->code_size, &list_bytes))
                    sink += codes.get()[list_bytes - 1];
                // get_single_code is the per-entry accessor (Panorama reconstructs into a fresh
                // buffer here), released through release_codes as its contract requires.
                faiss::InvertedLists::ScopedCodes one(il.get(), l, n - 1);
                if (one.get() && il->code_size) sink += one.get()[il->code_size - 1];
            } else if (bil && l < bil->codes.size() && bil->codes[l].size() > 0) {
                sink += bil->codes[l][bil->codes[l].size() - 1];
            }
        }
        (void)sink;
    } catch (const std::exception&) {
    }
    return 0;
}
