# Tofino 2 implementation of the CMSIS heavy-hitter detection algorithm
This repository contains a P4 implementation of the CMSIS heavy-hitter detection / frequency estimation algorithm.
The implementation was designed specifically to be run on Intel's Tofino 2 programmable switch.

Our implementation (cmsis.p4) consumes 6 pipeline stages out of the 20 stages available on Tofino 2. This implementation defines 64-bit registers that store 5-tuple flow identifiers.

We also provide an implementation (cmsis_32bit.p4) that uses 32-bit registers instead of 64-bit regisers, and therefore uses more registers to store the 5-tuple flow identifiers. The implementation with 32-bit registers consumes 8 pipeline stages.
