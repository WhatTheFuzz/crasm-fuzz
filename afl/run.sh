#!/bin/sh

# Call afl
afl-fuzz -i /input -o /output /crasm/src/crasm @@
