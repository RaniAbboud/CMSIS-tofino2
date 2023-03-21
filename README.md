# Tofino 2 implementation of the Voting Sketch heavy-hitter detection algorithm
This repository contains a P4 implementation of the Voting Sketch heavy-hitter / top-k detection / frequency estimation algorithm.
The implementation was designed specifically to be run on Intel's Tofino 2 programmable switch.

Our implementation consumes 7 pipeline stages out of the 20 stages available on Tofino 2.
