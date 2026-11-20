// faiss::read_VectorTransform on an untrusted byte stream, then apply / reverse_transform.
#include <memory>
#include <faiss/VectorTransform.h>
#include <faiss/impl/FaissException.h>
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
    std::unique_ptr<faiss::VectorTransform> vt;
    try {
        vt.reset(faiss::read_VectorTransform(&r));
    } catch (const std::exception&) {
        return 0;
    }
    if (!vt) return 0;
    if (vt->d_in <= 0 || vt->d_in > 4096 || vt->d_out <= 0 || vt->d_out > 4096) return 0;
    const uint8_t* tail = data + r.rp;
    const size_t tail_len = size - r.rp;
    try {
        std::vector<float> x = floats_from(tail, tail_len, vt->d_in);
        std::unique_ptr<float[]> y(vt->apply(1, x.data()));
        std::vector<float> back(vt->d_in);
        vt->reverse_transform(1, y.get(), back.data());
    } catch (const std::exception&) {
    }
    return 0;
}
