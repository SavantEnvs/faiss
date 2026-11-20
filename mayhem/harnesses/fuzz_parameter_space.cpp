// faiss::ParameterSpace::set_index_parameters on an untrusted parameter string, applied to a fresh
// clone of one of several small, pre-trained indexes, followed by a search.
// Input: byte 0 picks the index; the rest is the parameter string ("nprobe=4,efSearch=16,...").
#include <memory>
#include <random>
#include <string>
#include <faiss/AutoTune.h>
#include <faiss/Index.h>
#include <faiss/clone_index.h>
#include <faiss/impl/FaissException.h>
#include <faiss/IndexIVFPQ.h>
#include <faiss/index_factory.h>
#include "fuzz_common.h"

static const int D = 16, NT = 512;
static std::vector<std::unique_ptr<faiss::Index>> g_indexes; // read-only templates, cloned per input
static std::vector<float> g_xb;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    fuzz_faiss_init();
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> u(-1, 1);
    g_xb.resize(NT * D);
    for (auto& f : g_xb) f = u(rng);
    const char* descs[] = {"IVF4,PQ4x4np", "HNSW8", "PCA8,IVF4,Flat", "IVF4,SQ8",
                           "IVF4,Flat,RFlat", "LSH", "NSG8,Flat"};
    for (const char* s : descs) {
        std::unique_ptr<faiss::Index> idx(faiss::index_factory(D, s));
        // Keep start-up short (Mayhem's sanity check times out a slow LLVMFuzzerInitialize): the
        // templates only need to be trained, not well trained, so k-means runs a few iterations,
        // PQ skips polysemous training ("np") and NSG gets a smaller base.
        if (auto* ivf = dynamic_cast<faiss::IndexIVF*>(idx.get())) ivf->cp.niter = 2;
        if (auto* ivfpq = dynamic_cast<faiss::IndexIVFPQ*>(idx.get())) ivfpq->pq.cp.niter = 2;
        if (!idx->is_trained) idx->train(NT, g_xb.data());
        // NSG graph construction is slow under the instrumented build: a smaller base keeps it short.
        idx->add(std::string(s).rfind("NSG", 0) == 0 ? NT / 4 : NT, g_xb.data());
        g_indexes.push_back(std::move(idx));
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1 || size > 257) return -1;
    std::string params(reinterpret_cast<const char*>(data + 1), size - 1);
    if (params.find('\0') != std::string::npos) return -1;
    try {
        // A fresh copy per input: set_index_parameters mutates the index.
        std::unique_ptr<faiss::Index> idx(
                faiss::clone_index(g_indexes[data[0] % g_indexes.size()].get()));
        faiss::ParameterSpace ps;
        ps.set_index_parameters(idx.get(), params.c_str());
        const int nq = 2, k = 4;
        std::vector<float> Dis(nq * k);
        std::vector<faiss::idx_t> I(nq * k);
        idx->search(nq, g_xb.data(), k, Dis.data(), I.data());
    } catch (const std::exception&) {
    }
    return 0;
}
