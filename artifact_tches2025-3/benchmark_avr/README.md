# Benchmark on AVR
This folder contains the material to reproduce the benchmark results on the ATmega128.

## Folder sructure
Two different Microchip Studio projects are included, namely `cymric_aes` and `cymric_lwc` for the AES and the LWC benchmark, respectively.
```
benchmark_avr
├───README.md
├───scripts          //scripts for benchmarking
├───cymric_aes       //Microchip Studio project for AES benchmark
├───cymric_lwc       //Microchip Studio project for LWC benchmark
```

## Prerequisites
- [`Microchip Studio`](https://www.microchip.com/en-us/tools-resources/develop/microchip-studio) (we used the version 7.0.2594)

- `avr-gnu-toolchain` (the results reported in the paper were obtained using the version 14.1.0)

- `python3` for the script which extract code sizes

## Benchmarking
### Build process
The build process is handled by Microchip Studio itself, everything should run smoothly when launching the debugger.

### Speed results
Speed and stack results were directly obtained through Microchip Studio, in debug mode, by setting breakpoints and manually subtracting the before/after values in the Cycle Counter and Stack Pointer fields as shown in the screenshot below.
[Informations to look for in Debug mode](./screenshot_microchip.png "Microchip Studio screenshot in debug mode")

### Memory results
#### Stack
For the stack consumption, we added `-fstack-usage` to the compilation flags which produced `.su` files in the `Debug` folder and directly reported the stack consumption for each AEAD.

#### Size
From the `scripts` folder run
`python3 get_size.py ../cymric_aes/cymric_aes/Debug/cymric_aes.elf aes.json`
for the AES results and 
`python3 get_size.py ../cymric_lwc/cymric_lwc/Debug/cymric_lwc.elf lwc.json`
for the LWC results.

## License
By default the code in this repository is under CC0 license. However, some implementations considered for benchmarking purposes are taken from other proejcts and hence might be under other licenses. If so, a folder-specific LICENSE file will be included.
