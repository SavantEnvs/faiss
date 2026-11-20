// faiss::index_factory / index_binary_factory on an untrusted description string, then train,
// add and search on a small fixed dataset.
// Input: byte 0 picks d (1..64), float vs binary, and the metric; the rest is the description.
#include <cctype>
#include <memory>
#include <random>
#include <string>
#include <faiss/Index.h>
#include <faiss/IndexBinary.h>
#include <faiss/impl/FaissException.h>
#include <faiss/index_factory.h>
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    fuzz_faiss_init();
    return 0;
}

// Numeric parameters size allocations and training work directly (nlist, M, nbits, ...). Memory
// and CPU exhaustion from a huge requested size is the caller's choice, not a parser bug, so only
// descriptions whose integers are all <= 1024 are run.
static bool params_small(const std::string& s) {
    unsigned long long v = 0;
    bool in = false;
    for (char c : s) {
        if (std::isdigit((unsigned char)c)) {
            v = v * 10 + (c - '0');
            in = true;
            if (v > 1024) return false;
        } else {
            in = false;
            v = 0;
        }
    }
    (void)in;
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2 || size > 129) return -1;
    const uint8_t sel = data[0];
    std::string desc(reinterpret_cast<const char*>(data + 1), size - 1);
    if (desc.find('\0') != std::string::npos) return -1;
    if (!params_small(desc)) return -1;

    // 200 training points: enough for small IVF/PQ (<= 7 bits); an 8-bit PQ (256 centroids) is rejected
    // by Clustering up front instead of spending tens of seconds in k-means per input.
    const int nt = 200, nq = 2, k = 4;
    std::mt19937 rng(1234);
    try {
        if (sel & 0x80) {
            const int d = 8 * (1 + (sel & 7)); // binary d must be a multiple of 8
            std::unique_ptr<faiss::IndexBinary> idx(faiss::index_binary_factory(d, desc.c_str()));
            if (!idx) return 0;
            std::vector<uint8_t> xb(nt * d / 8);
            for (auto& b : xb) b = rng() & 0xff;
            if (!idx->is_trained) idx->train(nt, xb.data());
            idx->add(nt, xb.data());
            std::vector<int32_t> D(nq * k);
            std::vector<faiss::idx_t> I(nq * k);
            idx->search(nq, xb.data(), k, D.data(), I.data());
        } else {
            const int d = 1 + (sel & 63);
            faiss::MetricType metric = (sel & 0x40) ? faiss::METRIC_INNER_PRODUCT : faiss::METRIC_L2;
            std::unique_ptr<faiss::Index> idx(faiss::index_factory(d, desc.c_str(), metric));
            if (!idx) return 0;
            std::uniform_real_distribution<float> u(-1, 1);
            std::vector<float> xb(nt * d);
            for (auto& f : xb) f = u(rng);
            if (!idx->is_trained) idx->train(nt, xb.data());
            idx->add(nt, xb.data());
            std::vector<float> D(nq * k);
            std::vector<faiss::idx_t> I(nq * k);
            idx->search(nq, xb.data(), k, D.data(), I.data());
        }
    } catch (const std::exception&) {
    }
    return 0;
}
