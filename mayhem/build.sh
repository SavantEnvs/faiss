#!/usr/bin/env bash
#
# mayhem/build.sh — build faiss's fuzz harnesses (sanitized libfaiss.a) and its own gtest suite
# (normal flags). Runs inside the commit image as `mayhem` in /mayhem. Re-runnable and offline:
# every dependency is an apt package baked into the image (OpenBLAS, libomp, googletest sources).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Options common to both builds: CPU-only static library, no Python/GPU/MKL/demos.
COMMON=(-G Ninja -DFAISS_ENABLE_GPU=OFF -DFAISS_ENABLE_PYTHON=OFF -DFAISS_ENABLE_EXTRAS=OFF
        -DFAISS_ENABLE_MKL=OFF -DFAISS_ENABLE_C_API=OFF -DBUILD_SHARED_LIBS=OFF
        -DFAISS_OPT_LEVEL=generic -DBLA_VENDOR=OpenBLAS)

# 1) Sanitized + coverage-instrumented libfaiss.a for the harnesses. No CMAKE_BUILD_TYPE (that would
#    add -DNDEBUG); -O1 keeps the fuzzer fast. build/ is gitignored upstream.
FUZZ_FLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake -S . -B build/fuzz "${COMMON[@]}" -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE= \
      -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS"
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target faiss

# 2) Harnesses: each linked twice — libFuzzer binary and a run-once -standalone reproducer.
HFLAGS=(-std=c++20 -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fopenmp -I"$SRC" -I"$SRC/mayhem/harnesses")
LIBS=("$SRC/build/fuzz/faiss/libfaiss.a" -lopenblas -fopenmp -lpthread -lm)
mkdir -p build/harness
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/harness/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/harness/standalone_main.o
for h in fuzz_read_index fuzz_read_index_binary fuzz_read_vector_transform fuzz_read_pq \
         fuzz_read_invlists fuzz_index_factory fuzz_parameter_space; do
  $CXX "${HFLAGS[@]}" -fsanitize=fuzzer-no-link -c "mayhem/harnesses/$h.cpp" -o "build/harness/$h.o"
  $CXX "${HFLAGS[@]}" $LIB_FUZZING_ENGINE "build/harness/$h.o" build/harness/lsan_off.o "${LIBS[@]}" \
       -o "$SRC/$h"
  $CXX "${HFLAGS[@]}" build/harness/standalone_main.o "build/harness/$h.o" build/harness/lsan_off.o \
       "${LIBS[@]}" -fsanitize=fuzzer-no-link -o "$SRC/$h-standalone"
done

# 3) Upstream's gtest suite (tests/faiss_test) with NORMAL flags. googletest comes from the apt
#    package's sources instead of tests/CMakeLists.txt's FetchContent git clone, and perf_tests'
#    google/benchmark from the pinned copy under /opt/toolchains/deps (configured, not built): offline.
cmake -S . -B build/test "${COMMON[@]}" -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release \
      -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=/usr/src/googletest \
      -DFETCHCONTENT_SOURCE_DIR_GOOGLEBENCHMARK=/opt/toolchains/deps/benchmark-1.9.4/src \
      -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build/test -j"$MAYHEM_JOBS" --target faiss_test
