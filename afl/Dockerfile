FROM aflplusplus/aflplusplus as FUZZER

# Copy over the source code and input/output files.
COPY ./crasm /crasm
COPY ./run.sh /

WORKDIR /crasm

# Compile the target.
RUN CC=afl-clang-lto CXX=afl-clang-lto++ make

WORKDIR /

# Run the fuzzer.
CMD ["/run.sh"]