// faiss::read_index on an untrusted byte stream, then one operation on the loaded index.
// Input: byte 0 selects the operation; the rest is the serialized index, and whatever the reader
// does not consume becomes query/code data for the operation.
#include <memory>
#include <faiss/Index.h>
#include <faiss/clone_index.h>
#include <faiss/impl/AuxIndexStructures.h>
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
    std::unique_ptr<faiss::Index> idx;
    try {
        idx.reset(faiss::read_index(&r, 0));
    } catch (const std::exception&) {
        return 0;
    }
    if (!idx) return 0;
    const faiss::idx_t d = idx->d;
    // Queries are d floats each; keep them small (d comes from the stream).
    if (d <= 0 || d > 4096) return 0;
    const uint8_t* tail = data + 1 + r.rp;
    const size_t tail_len = (size - 1) - r.rp;
    try {
        switch (op % 5) {
            case 0: { // k-NN search, k=4, 2 queries from the tail (NaN possible)
                const faiss::idx_t n = 2, k = 4;
                std::vector<float> q = floats_from(tail, tail_len, n * d);
                std::vector<float> D(n * k);
                std::vector<faiss::idx_t> I(n * k);
                idx->search(n, q.data(), k, D.data(), I.data());
                break;
            }
            case 1: { // range search
                std::vector<float> q = floats_from(tail, tail_len, d);
                float radius = tail_len ? float(tail[0]) : 1.0f;
                faiss::RangeSearchResult res(1);
                idx->range_search(1, q.data(), radius, &res);
                break;
            }
            case 2: { // reconstruct the first stored vectors (ids within [0, ntotal))
                std::vector<float> x(d);
                for (faiss::idx_t i = 0; i < idx->ntotal && i < 4; i++)
                    idx->reconstruct(i, x.data());
                break;
            }
            case 3: { // standalone codec: decode codes taken from the tail, then re-encode
                size_t cs = idx->sa_code_size();
                if (cs == 0 || cs > (1u << 16)) break;
                std::vector<uint8_t> codes(2 * cs);
                for (size_t i = 0; i < codes.size(); i++)
                    codes[i] = tail_len ? tail[i % tail_len] : 0;
                std::vector<float> x(2 * d);
                idx->sa_decode(2, codes.data(), x.data());
                idx->sa_encode(2, x.data(), codes.data());
                break;
            }
            case 4: { // re-serialize, clone, and read the re-serialized bytes back
                faiss::VectorIOWriter w;
                faiss::write_index(idx.get(), &w);
                std::unique_ptr<faiss::Index> c(faiss::clone_index(idx.get()));
                faiss::VectorIOReader vr;
                vr.data = w.data;
                std::unique_ptr<faiss::Index> again(faiss::read_index(&vr, 0));
                break;
            }
        }
    } catch (const std::exception&) {
    }
    return 0;
}
