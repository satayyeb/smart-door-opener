# Repository Guidelines

## Project Structure & Module Organization

This repository contains native C firmware for the ESP8266 RTOS SDK `release/v3.4`; it is not a modern ESP-IDF or Arduino project. Application code lives in `main/`: `main.c` initializes hardware and services, while `door_captive`, `door_config`, `door_control`, `door_wifi`, `door_web`, `door_socket`, and `door_ota` separate captive setup, persistence, relay control, networking, panel UI, WebSocket behavior, and signed updates. Keep each module's public declarations in its matching `.h` file. Embedded trust roots are under `main/certs/`. Root-level `sdkconfig.defaults` and `partitions.csv` define build and flash defaults.

## Build, Test, and Development Commands

Activate the legacy SDK environment in every shell. On the documented workstation, run:

```sh
esp-lagecy
idf.py build
idf.py menuconfig
idf.py -p /dev/ttyUSB0 flash monitor
```

`idf.py build` produces `build/smart-door-opener.bin`; `menuconfig` edits SDK configuration; `flash monitor` programs the complete image and opens the 115200-baud serial console. Use the Python environment installed with ESP8266 RTOS SDK v3.4, and confirm `python "$IDF_PATH/tools/check_python_dependencies.py"` succeeds when troubleshooting setup.

## Coding Style & Naming Conventions

Follow the existing C style: four-space indentation, opening braces on the same line, `snake_case` functions and variables, and uppercase macros such as `DOOR_CONFIG_VERSION`. Prefix exported module functions with `door_`; keep file-local helpers and state `static`. Check every ESP SDK return value and avoid logging Wi-Fi passwords, authorization tokens, or other secrets. Keep blocking work out of callbacks and preserve bounded buffers and message-size checks.

## Testing Guidelines

There is currently no firmware unit-test framework or coverage gate. Every change must compile cleanly with `idf.py build` and fit both `0xe0000` OTA slots. For hardware-sensitive changes, test provisioning, Wi-Fi reconnects, WebSocket authentication, OTA rejection, and relay timing as applicable. Verify relay polarity with the lock disconnected, and confirm malformed or oversized messages cannot actuate GPIO 12. Include relevant serial-log evidence while redacting credentials.

## Commit & Pull Request Guidelines

The short history does not establish a commit convention. Use concise, imperative subjects such as `Harden WebSocket frame validation`, and keep commits focused. Pull requests should explain behavior and safety impact, list build and device checks, link the issue when available, and include screenshots for setup-page changes. Call out changes to NVS layout, partitioning, GPIO behavior, server protocol, or the embedded CA certificate explicitly.

## Security & Configuration Tips

Do not disable TLS or signature validation. Never commit device credentials or the OTA private key. Increment `DOOR_CONFIG_VERSION` deliberately when changing persisted structure, and document migration or reset behavior. Keep release asset names, GitHub paths, the public key, and `.github/workflows/release.yml` synchronized with `door_ota.c`.
