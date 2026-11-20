// faiss::read_ProductQuantizer on an untrusted byte stream, then encode / decode / distance tables.
#include <memory>
#include <faiss/impl/FaissException.h>
#include <faiss/impl/ProductQuantizer.h>
#include <faiss/impl/io.h>
#include <faiss/index_io.h>
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
    std::unique_ptr<faiss::ProductQuantizer> pq;
    try {
        pq.reset(faiss::read_ProductQuantizer(&r));
    } catch (const std::exception&) {
        return 0;
    }
    if (!pq) return 0;
    // Work buffers are d floats, code_size bytes and M*ksub floats.
    if (pq->d == 0 || pq->d > 4096 || pq->code_size == 0 || pq->code_size > 4096 ||
        pq->M * pq->ksub > (1u << 20))
        return 0;
    const uint8_t* tail = data + r.rp;
    const size_t tail_len = size - r.rp;
    try {
        std::vector<float> x = floats_from(tail, tail_len, pq->d);
        std::vector<uint8_t> code(pq->code_size);
        pq->compute_code(x.data(), code.data());
        std::vector<float> x2(pq->d);
        pq->decode(code.data(), x2.data());
        std::vector<float> table(pq->M * pq->ksub);
        pq->compute_distance_table(x.data(), table.data());
    } catch (const std::exception&) {
    }
    return 0;
}
