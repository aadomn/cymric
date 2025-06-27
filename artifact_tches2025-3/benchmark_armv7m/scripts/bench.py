#!/usr/bin/env python3
import argparse
import serial
import serial.tools.list_ports

def select_serial_port():
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        raise RuntimeError("No serial ports found.")
    if len(ports) == 1:
        return ports[0].device
    print("Available serial ports:")
    for i, port in enumerate(ports):
        print(f"{i}: {port.device} ({port.description})")
    idx = int(input("Select port number: "))
    return ports[idx].device

def main():
    parser = argparse.ArgumentParser(description="Run benchmark on device.")
    parser.add_argument('--port', type=str, help='Serial port (e.g., /dev/ttyUSB0)')
    args = parser.parse_args()
    
    port = args.port
    if port is None:
        port = select_serial_port()

    try:
        ser = serial.Serial(port, 115200, timeout=1)
        print(f"Connected to {port}")
        while True:
            print("> Returned data:", file=sys.stderr)
            x = dev.read()
            sys.stdout.buffer.write(x)
            sys.stdout.flush()
        ser.close()
    except serial.SerialException as e:
        print(f"Could not open serial port {port}: {e}")

if __name__ == "__main__":
    main()
