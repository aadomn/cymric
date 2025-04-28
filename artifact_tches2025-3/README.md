# Artifact for the paper "Cymric: Short-tailed but Mighty. Beyond-birthday-bound Secure Authenticated Encryption for Short Inputs"

## Overview
This artifact aims at giving details on how to reproduce our benchmarking results reported in the paper entitled "Cymric: Short-tailed but Mighty" published in TCHES 2025/3.
Since two benchmarking platforms are considered, the artifact consists in two folders as described below:
```
cymric_artifact
│   README.md
│
├───benchmark_armv7m
├───benchmark_avr
```
where `benchmark_arm` and `benchmark_avr` contain the necessary material to run the benchmarks on the 32-bit ARM and 8-bit AVR platforms, respectively.

## Benchmarks on ARMv7M
The ARM benchmarks were run on a real board where all details are listed in the folder-specific README.
Our development environment was under Ubuntu 20.04.6.

## Benchmarks on AVR
The AVR benchmarks however were not run on a real board but with an ATmega128 simulator using Microchip Studio v7.0.2594 (available on Windows only).
While it is less easy to reproduce the results in a scripted/automated manner with this setting, the required material and instructions to do so are nevertheless provided in the corresponding folder.

## License
By default the code in this repository is under CC0 license. However, some implementations considered for benchmarking purposes are taken from other proejcts and hence might be under other licenses. If so, a folder-specific LICENSE file will be included.