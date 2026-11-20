// faiss::read_index_binary on an untrusted byte stream, then a k-NN search (or re-serialize+clone).
#include <memory>
#include <faiss/IndexBinary.h>
#include <faiss/clone_index.h>
#include <faiss/impl/FaissException.h>
#include <faiss/impl/io.h>
#include <faiss/index_io.h>
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    fuzz_faiss_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return -1;
    const uint8_t op = data[0];
    // VectorIOReader owns an aligned copy (ZeroCopyIOReader would hand out views at arbitrary,
    // misaligned offsets of the fuzzer buffer, which is a harness artifact, not a faiss bug).
    faiss::VectorIOReader r;
    r.data.assign(data + 1, data + 1 + size - 1);
    std::unique_ptr<faiss::IndexBinary> idx;
    try {
        idx.reset(faiss::read_index_binary(&r, 0));
    } catch (const std::exception&) {
        return 0;
    }
    if (!idx) return 0;
    // Binary indexes store d bits per vector; queries are d/8 bytes.
    if (idx->d <= 0 || idx->d > 8 * 4096 || idx->d % 8 != 0) return 0;
    const uint8_t* tail = data + 1 + r.rp;
    const size_t tail_len = (size - 1) - r.rp;
    try {
        if (op % 2 == 0) {
            const faiss::idx_t n = 2, k = 4;
            const size_t cs = idx->d / 8;
            std::vector<uint8_t> q(n * cs);
            for (size_t i = 0; i < q.size(); i++) q[i] = tail_len ? tail[i % tail_len] : 0;
            std::vector<int32_t> D(n * k);
            std::vector<faiss::idx_t> I(n * k);
            idx->search(n, q.data(), k, D.data(), I.data());
        } else {
            faiss::VectorIOWriter w;
            faiss::write_index_binary(idx.get(), &w);
            std::unique_ptr<faiss::IndexBinary> c(faiss::clone_binary_index(idx.get()));
        }
    } catch (const std::exception&) {
    }
    return 0;
}
