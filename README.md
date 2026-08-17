# Smart Door Opener for ESP8266

Native ESP8266 RTOS SDK firmware for an ESP8266EX controlling a door relay. It
replaces the original Arduino/PlatformIO firmware while preserving its server
protocol and GPIO 12 relay wiring.

This is an **ESP8266 RTOS SDK release/v3.4** project. It is not an ESP32 ESP-IDF
project and must not be built with a normal modern ESP-IDF installation.

## Features

- One-time `SmartDoor-XXXXXXXX` WPA/WPA2 setup access point, enabled only during
  initial provisioning or after factory reset.
- Configuration page at `http://192.168.4.1` during setup only; it is not served
  after provisioning.
- NVS-backed list of up to five Wi-Fi SSID/password pairs, WebSocket endpoint,
  and authorization header.
- Native ESP8266 RTOS SDK HTTP server and WebSocket transport.
- `ws://` and certificate-validated `wss://` connections.
- SNTP clock synchronization before TLS certificate validation.
- Reconnect, ping/pong, bounded WebSocket messages, and JSON validation.
- Non-blocking 300 ms GPIO 12 relay pulse with overlapping-command protection.
- Active-low GPIO 2 status LED: solid while station Wi-Fi is disconnected,
  blinking while Wi-Fi is connected but WebSocket is not, and off while the
  WebSocket is operational.
- Physical configuration reset by holding GPIO 0 low for ten seconds while the
  firmware is already running.
- No remote binary-update command. The original unsigned WebSocket OTA mechanism
  allowed a compromised server or token to replace the firmware.

## Initial credentials

There is no website login. The setup AP uses an eight-character hexadecimal
password equal to the suffix in its SSID. For example,
`SmartDoor-A1B2C3D4` uses `A1B2C3D4` as its password.

## First setup

1. Flash the complete ESP8266 image and open the serial monitor at 115200 baud.
2. Let the board boot normally. Do not hold GPIO 0 low during reset because that
   selects the ESP8266 serial bootloader.
3. Join `SmartDoor-XXXXXXXX` with the same eight hexadecimal characters as its
   password (for example, `SmartDoor-A1B2C3D4` uses `A1B2C3D4`).
4. Open `http://192.168.4.1`; no login is required.
5. Enter one or more home Wi-Fi SSID/password pairs, keep or change the default WebSocket URI
   (`wss://door.alitayyeb.ir/ws/1`), and enter the optional `Authorization`
   header value.
6. Save. The board reboots, disables its setup AP and configuration page, connects to the
   selected Wi-Fi, and starts the outbound WebSocket client.

Passwords and tokens are never written to serial logs.

## WebSocket protocol

The firmware accepts complete JSON text messages up to 1024 bytes:

```json
{"command":"get-version"}
{"command":"open-door"}
```

It returns the original response shape:

```json
{"success":true,"message":"Door opened successfully."}
```

`open-door` asserts GPIO 12 high for 300 ms. A second command while the relay is
active is rejected. Unknown commands, malformed JSON, binary frames, and
oversized frames cannot actuate the relay.

When an authorization value is configured, the WebSocket upgrade contains:

```http
Authorization: <configured value>
```

Enter the complete value expected by the server, such as `Bearer TOKEN`, if the
server uses a scheme.

## TLS certificate

[`main/certs/server_root_ca.pem`](main/certs/server_root_ca.pem) currently contains
the ISRG Root X1 certificate for Let's Encrypt endpoints. Certificate hostname,
chain, and validity checks remain enabled. Before deploying against a server
using another certificate authority, replace this file with that server's root
CA certificate and rebuild. Do not work around a TLS failure by switching to
`ws://` or disabling validation on an Internet connection.

The ESP8266 synchronizes its clock using `pool.ntp.org` before initiating TLS.
DNS, NTP (UDP 123), and the WebSocket destination must therefore be reachable.

## Development prerequisites

This firmware requires the legacy **ESP8266 RTOS SDK `release/v3.4`**. A modern
ESP-IDF installation targets ESP32-family chips and cannot build this project.
The required host tools are Git, CMake, Make, and Python with virtual-environment
support.

Clone the SDK with all submodules and install its Xtensa toolchain and pinned
Python packages:

```sh
mkdir -p "$HOME/esp"
cd "$HOME/esp"
git clone --recursive --branch release/v3.4 \
  https://github.com/espressif/ESP8266_RTOS_SDK.git
cd ESP8266_RTOS_SDK
./install.sh
```

`install.sh` creates a versioned environment under
`$HOME/.espressif/python_env/`, for example
`rtos3.4_py3.14_env`. Activate that environment **before** loading the SDK. This
is important on systems whose `/usr/bin/python` has newer, incompatible versions
of `cryptography` or `pyparsing`:

```sh
. "$HOME/.espressif/python_env/rtos3.4_py3.14_env/bin/activate"
. "$HOME/esp/ESP8266_RTOS_SDK/export.sh"
```

Replace `py3.14` with the directory created on the local machine. The activation
worked when `python "$IDF_PATH/tools/check_python_dependencies.py"` reports that
all requirements are satisfied.

For this workstation, the same setup is available through the intentionally
named `esp-lagecy` Bash alias. Its definition in `~/.bashrc` is:

```sh
alias esp-lagecy='source "$HOME/.espressif/python_env/rtos3.4_py3.14_env/bin/activate" && source "$HOME/esp/ESP8266_RTOS_SDK/export.sh"'
```

Open a new terminal after adding or changing the alias.

## Configure and build

Load the legacy environment in every new terminal, then build:

```sh
cd /home/ali/own/smart-door-opener
esp-lagecy
idf.py menuconfig
idf.py build
```

The project sets `CMAKE_POLICY_VERSION_MINIMUM=3.5` itself so that the old SDK
can be configured by CMake 4. No extra `-D` option is required. Deprecation
warnings from the SDK's old CMake and Python APIs are expected; a successful
build ends with `Project build complete` and creates `build/smart-door-opener.bin`.

If the SDK reports unsatisfied Python requirements, check `command -v python`.
It must resolve inside `~/.espressif/python_env/rtos3.4_..._env/bin`, not to
`/usr/bin/python`.

## Flash and monitor

Connect the board, identify its serial port, and grant the current user access
to that port according to the host distribution. Then run:

```sh
esp-lagecy
cd /home/ali/own/smart-door-opener
idf.py -p /dev/ttyUSB0 flash monitor
```

Exit the serial monitor with `Ctrl+]`. Replace `/dev/ttyUSB0` if the adapter uses
another device such as `/dev/ttyUSB1` or `/dev/ttyACM0`.

Confirm the detected flash size in `menuconfig`. The supplied partition table
uses a single 1 MiB application partition and fits common 2 MiB and 4 MiB
ESP8266 modules. Do not flash only the application at an assumed offset on the
first installation; use `idf.py flash` so the matching bootloader, partition
table, PHY data, and application are written to their correct offsets.

## IntelliJ IDEA setup

`c_cpp_properties.json` is a Visual Studio Code file and has no effect in
IntelliJ IDEA. IDEA needs its **C/C++** and **Compilation Database** plugins.
After `idf.py build` has generated `build/compile_commands.json`:

1. Close the currently opened project in IDEA.
2. From the welcome screen, choose **Open** and select
   `build/compile_commands.json`.
3. Choose **Open as Project**.
4. Select **Tools > Compilation Database > Change Project Root** and choose the
   repository root, `/home/ali/own/smart-door-opener`.
5. After a build changes the database, select **Tools > Compilation Database >
   Reload Compilation Database Project**, or press `Ctrl+Shift+O`.

Build and flash from IDEA's terminal with the same `esp-lagecy` and `idf.py`
commands. The compilation database supplies IDEA with the real Xtensa compiler,
SDK include directories, generated headers, preprocessor definitions, and
per-file compiler flags; manually adding include paths is neither necessary nor
equivalent.

The firmware has been successfully compiled with ESP8266 RTOS SDK
`release/v3.4`, Xtensa GCC 8.4.0, Python 3.14.4 in the SDK environment, and CMake
4.2.3.

## Recovery and deployment safety

- To erase only the door configuration, boot normally and then hold GPIO 0 low
  continuously for ten seconds. Releasing it early cancels the operation. The
  board restarts in setup mode with a newly generated SSID/password pair.
- Verify relay polarity with the lock disconnected. The code assumes an
  active-high relay on GPIO 12, preloads the inactive level before enabling the
  output, and initializes it before NVS or networking.
- Add an external pull-down to the relay driver so the door cannot pulse while
  the ESP8266 is resetting or before firmware configures GPIO 12. Firmware
  cannot control the pin during the ROM bootloader interval, so this resistor is
  required for a hardware guarantee that the relay never powers during reboot.
- The local configuration site uses HTTP, not HTTPS, and has no login. It exists
  only on the setup AP during first initialization or after factory reset; it is
  not reachable on the home LAN after provisioning.
- The setup AP is enabled only during initial provisioning and after a factory
  reset. Its eight-character hexadecimal password is the same suffix shown in
  its SSID.
- Use a unique, device-scoped server token and enforce authorization and rate
  limiting on the WebSocket server as well as on the device.
- NVS stores Wi-Fi and server credentials in recoverable form unless flash/NVS
  encryption is enabled and supported by the chosen ESP8266 deployment.
