# Tofino 2 implementation of the CMSIS heavy-hitter detection algorithm
This repository contains a P4 implementation of the CMSIS (Count-Min Sketch with Identifier Sampling) heavy-hitter detection / frequency estimation algorithm.
The implementation was designed specifically to be run on Intel's Tofino 2 programmable switch.

The implementation (_cmsis.p4_) consumes 6 pipeline stages out of the 20 stages available on Tofino 2. This implementation defines 64-bit registers that store 5-tuple flow identifiers.

An alternative implementation (_cmsis_32bit.p4_) uses 32-bit registers instead of 64-bit regisers as the latter are not available on Tofino 1. This 32-bit version needs twice the number of registers (arrays) needed by the 64-bit version to store the 5-tuple flow identifiers, therefore consuming 8 pipeline stages.

In addition, we provide an implementation (_cms_threshold.p4_) for a simple adaption of Count-Min sketch which performs online heavy hitter detection, but does not support offline retrieval of the heavy hitters' identifiers, as it does not store flow identifiers. This algorithm consumes only 3 pipeline stages.

## Architecture
### CMSIS
<img src=https://github.com/RaniAbboud/CMSIS-tofino2/assets/47865109/f2c48a0a-cdbe-4718-9913-dac10b7d4e56 width=400>

CMSIS is based on a 2-way Count-Min sketch, and maintains a structure that stores identifiers of flows suspected to be heavy hitters.

### CMS+Threshold
<img src=https://github.com/RaniAbboud/CMSIS-tofino2/assets/47865109/56111a53-ff30-45c9-b255-553e5b58a0d8 width=280>

CMS+Threshold is an adaption of Count-Min sketch for heavy hitter detection.
