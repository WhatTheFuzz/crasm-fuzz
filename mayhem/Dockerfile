FROM aflplusplus/aflplusplus as COMPILER

# Copy over the source code.
COPY ./crasm /
WORKDIR /crasm

# Compile the target.
RUN CC=afl-clang-lto CXX=afl-clang-lto++ make

FROM ubuntu:22.04 as RUNNER

COPY --from=COMPILER /crasm /crasm
# Copy the seeds to the corpus files.
RUN mkdir /testsuite && cp -r /crasm/test/* /testsuite
