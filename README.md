# Tofino 2 implementation of the CMSIS heavy-hitter detection algorithm
This repository contains a P4 implementation of the CMSIS heavy-hitter detection / frequency estimation algorithm.
The implementation was designed specifically to be run on Intel's Tofino 2 programmable switch.

The implementation (_cmsis.p4_) consumes 6 pipeline stages out of the 20 stages available on Tofino 2. This implementation defines 64-bit registers that store 5-tuple flow identifiers.

We also provide an implementation (_cmsis_32bit.p4_) that uses 32-bit registers instead of 64-bit regisers as the latter are not available on Tofino 1. This 32-bit version needs twice the number of registers (arrays) needed by the 64-bit version to store the 5-tuple flow identifiers, therefore consuming 8 pipeline stages.
