# Benchmark on ARMv7-M
This folder contains the material to reproduce the benchmark results on the ARM Cortex-M4.

## Folder sructure
```
benchmark_armv7m
├───README.md
├───scripts          //scripts for benchmarking
├───stm32f4          //board-related files
├───aes              //AES benchmark
│   ├───aes          //underlying aes implementation
│   ├───modes        //each operating mode has its own folder
│   │   ├───cymric
│   │   ├───gcm
│   │   ├───gcmsiv
│   │   ├───ocb
│   │   └───xocb
│   ├───main.c
│   └───Makefile
├───lwc              //LWC benchmark where each AEAD has its own folder
│   ├───asconaead128
│   ├───cymric
│   │   ├───gift
│   │   └───lea
│   ├───giftcofb
│   ├───photonbeetle
│   ├───romulusn
│   ├───xoodyak
│   ├───main.c
│   └───Makefile
```

## libopencm3 submodule
This repository uses [libopencm3](https://github.com/libopencm3/libopencm3) as a submodule, pinned to commit for reproducibility.

To clone with submodules:
```
git clone --recursive https://github.com/aadomn/cymric/git
```

Or if already cloned:
```
git submodule update --init --recursive
```

And run `make TARGETS='stm32f4` inside the `libopencm3` directory.

## Prerequisites
### Software
- `arm-gnu-toolchain` (the results reported in the paper were obtained using the version 14.2.1)

make TARGETS='stm32/f4'

- [`st-link`](https://github.com/stlink-org/stlink) to flash the binaries

- `python3` with the [`pySerial`](https://pypi.org/project/pyserial/) module for serial communications to `\dev\ttyUSB0`
### Hardware
- [STM32F407G-DISC1](https://www.st.com/en/evaluation-tools/stm32f4discovery.html) development board
- USB to TTL adapter

## Benchmarking
### Build process
Both makefiles in `aes` and `lwc` assume that the `libopencm3` directory is located at the root of this folder (i.e. `artifact_tches2025-3/benchmark_armv7m`).
If not, it is necessary modify `OPENCM3DIR` accordingly.
Similarly, make sure that the `ARMNONEEABIDIR` points to the right location on your system.

Running `make` should produce the `firmware_m4.bin` and `firmware_m4.elf` in the respective folders.

### Speed results
Once the build process is complete, one can flash the binary by running `make flash`.
Then to execute the benchmark, one has to run `python3 ../scripts/bench.py` and reset the board.
Note that according to `stm32f4_wrapper.c`, the USB to TTL adapter must connect TX and RX to PA3 and PA2, respectively.

### Memory results
From the `scripts` folder run
`python3 memory_analyzer.py ../aes/firmware_m4.elf --functions_file functions_aes_benchmark.json`
for the AES results and
`python3 memory_analyzer.py ../lwc/firmware_m4.elf --functions_file functions_lwc_benchmark.json`
for the LWC results.

## License
By default the code in this repository is under CC0 license. However, some implementations considered for benchmarking purposes are taken from other proejcts and hence might be under other licenses. If so, a folder-specific LICENSE file will be included.
