# AFL Harness

## Running the Fuzzer

```shell
docker build --no-cache --tag crasm-afl .
docker run --volume $(pwd)/input:/input --volume $(pwd)/output:/output crasm-afl
```