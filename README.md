# Smart Door Opener for ESP8266

Native ESP8266 RTOS SDK firmware for an ESP8266EX controlling a door relay. It
replaces the original Arduino/PlatformIO firmware while preserving its server
protocol and GPIO 12 relay wiring.

This is an **ESP8266 RTOS SDK release/v3.4** project. It is not an ESP32 ESP-IDF
project and must not be built with a normal modern ESP-IDF installation.

## Features

- One-time open `SmartDoor-XXXXXXXX` setup access point, enabled only during
  initial provisioning or after factory reset.
- Captive-portal detection redirects newly connected phones and computers to
  `http://192.168.4.1` automatically.
- Configuration page at `http://192.168.4.1` during setup and on the station LAN
  after provisioning, with an optional user-configured password.
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
- Signed dual-slot OTA updates from the panel, GitHub Releases, or an
  authenticated backend command, with visible download progress.
- Physical configuration reset by holding GPIO 0 low for five seconds while the
  firmware is already running.
- No remote binary-update command. The original unsigned WebSocket OTA mechanism
  allowed a compromised server or token to replace the firmware.

## Initial access

The initial `SmartDoor-XXXXXXXX` setup network is open and has no password. It
is disabled immediately after the first valid configuration is saved. The LAN
panel also starts without a password; one can be set later under **Panel
access**. When enabled, the username is `admin`.

## First setup

1. Flash the complete ESP8266 image and open the serial monitor at 115200 baud.
2. Let the board boot normally. Do not hold GPIO 0 low during reset because that
   selects the ESP8266 serial bootloader.
3. Join the open `SmartDoor-XXXXXXXX` network. The operating system should open
   the setup panel automatically through captive-portal detection.
4. If the panel does not appear, open `http://192.168.4.1`; no login is required.
5. Enter one or more home Wi-Fi SSID/password pairs, keep or change the default WebSocket URI
   (`wss://door.alitayyeb.ir/ws/1`), and enter the optional `Authorization`
   header value.
6. Save. The board reboots, disables its setup AP, connects to the selected
   Wi-Fi, starts the outbound WebSocket client, and serves the panel on its LAN
   IP address.

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
Authorization: Bearer <device token>
```

Bare device tokens automatically receive the `Bearer ` prefix. You can also
enter a complete header value, such as `Bearer TOKEN` or another scheme
required by your server.

## TLS certificate

[`main/certs/server_root_ca.pem`](main/certs/server_root_ca.pem) contains
only directly trusted intermediate CAs:
Let's Encrypt YR1 (door endpoint and release assets), plus Sectigo Public
Server Authentication CA DV E36 (GitHub). E36 was verified against Sectigo
Root E46; rotate it before **2036-03-21**, or if GitHub changes issuer.
YR1 is a direct trust anchor for `door.alitayyeb.ir`: the legacy ESP8266 TLS
verifier rejects its longer chain through Root YR to ISRG Root X1. YR1 was
verified against ISRG Root X1 before embedding; rotate it before its expiry
on **2028-09-02**, or if the endpoint changes issuer. Certificate hostname,
signature, and validity checks remain enabled. For another issuer, add its verified CA and rebuild. Do not
switch to `ws://` or disable validation to work around TLS failures.

TLS uses SDK dynamic buffers (16 KB receive limit, 1 KB transmit limit) and
frees handshake certificate data to leave room for RSA operations on the
ESP8266. The receive limit supports full-size TLS records from GitHub.
These settings are in `sdkconfig.defaults`; existing builds must also apply them to `sdkconfig`
through `idf.py menuconfig` or regenerate `sdkconfig`.

The ESP8266 starts synchronization through `pool.ntp.org`. If NTP is blocked,
it uses firmware build time as an initial lower bound for TLS while
continuing to synchronize in the background.

## Signed firmware updates

The panel's **Check for firmware updates** button downloads the latest signed
manifest from GitHub Releases. It shows check, download, verification, and
restart progress, and asks for confirmation before installation. The firmware
verifies the manifest with `main/certs/ota_public_key.pem`, then verifies the
downloaded image's SHA-256 before selecting the inactive OTA slot. The backend
can start the same process with the authenticated `update-firmware` WebSocket
command.

The private signing key is never stored here. GitHub Actions expects it as the
base64-encoded `OTA_SIGNING_KEY_B64` repository secret. Every push to `main`
builds version `0.1.<run number>`, signs its manifest, uploads an Actions
artifact, and publishes the files as the latest GitHub Release.

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
uses two 896 KiB OTA application slots and requires at least 2 MiB of flash.
Do not flash only the application at an assumed offset on the
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

## OTA layout migration and recovery

The ESP8266 maps flash in 1 MiB windows. Both slots must have the same offset
within their window for one linked binary: `ota_0` at `0x20000`, `ota_1` at
`0x120000`, each `0xe0000` bytes. The former `ota_1` at `0x100000` passed SDK
image checks but booted with the wrong cache mapping and watchdog-reset before
`app_main`. An application-only OTA cannot update the partition table.

For a board stuck after that update, disconnect the lock and use USB serial:

```sh
esp-lagecy
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

This writes the corrected partition table, resets OTA selection to `ota_0`,
and flashes the application. It preserves NVS Wi-Fi and panel settings;
do not use `erase_flash`. If needed, hold GPIO 0 low during reset to enter ROM
serial download mode, then release it before normal boot.

Failed/truncated downloads or bad hashes never select the downloaded slot.
The firmware also rejects incompatible image link origins before selecting a
slot. SDK v3.4 has no automatic rollback for a checksum-valid application that
crashes before startup; that requires a separate bootloader change and serial
installation. Do not treat image validation as a successful device boot.

Run host checks after building:

```sh
python3 tests/check_ota_redirects.py
python3 tests/check_ota_safety.py
```

Device acceptance checks: interrupt download around 70%, confirm the original
firmware still runs after reset, then complete updates in both directions and
confirm the boot offsets alternate between `0x20000` and `0x120000`. Keep the
lock disconnected throughout these checks.

## Recovery and deployment safety

- To erase only the door configuration, boot normally and then hold GPIO 0 low
  continuously for five seconds. Releasing it early cancels the operation. The
  board restarts with a newly generated open setup SSID.
- Verify relay polarity with the lock disconnected. The code assumes an
  active-high relay on GPIO 12, preloads the inactive level before enabling the
  output, and initializes it before NVS or networking.
- Add an external pull-down to the relay driver so the door cannot pulse while
  the ESP8266 is resetting or before firmware configures GPIO 12. Firmware
  cannot control the pin during the ROM bootloader interval, so this resistor is
  required for a hardware guarantee that the relay never powers during reboot.
- The local panel uses HTTP, not HTTPS. It remains reachable on the home LAN;
  configure its optional password if the LAN is not fully trusted.
- The setup AP is enabled only during initial provisioning and after a factory
  reset. It is open, so complete setup promptly and do not expose setup mode in
  an untrusted area.
- Use a unique, device-scoped server token and enforce authorization and rate
  limiting on the WebSocket server as well as on the device.
- NVS stores Wi-Fi and server credentials in recoverable form unless flash/NVS
  encryption is enabled and supported by the chosen ESP8266 deployment.

## RC522 cards (MIFARE Classic 1K)

Card scans open the door without a phone or PIN. The LAN panel can enroll and
remove up to 16 named cards, including names such as `Ali's card`. Enrollment
requires a provisioned device and a panel password; sign in as `admin`. This
password protects administration only, not ordinary card scans.

**Security limitation:** Classic 1K's Crypto1 remains vulnerable to key recovery
and cloning. This firmware does not authorize by UID alone: it authenticates
sector 7 using a random per-card 48-bit Key A, reads a random 128-bit credential
from block 28, and compares it against the stored credential. UID only selects
the expected record/key. Copying only the UID or presenting a factory-key card
cannot pass those checks. Copying the UID, recovered key, and credential can
still open the door. This is not AES authentication or clone-resistant access.
NVS contains recoverable card keys/credentials; protect physical access to the
controller. The HTTP panel also requires a trusted LAN; Basic authentication
does not encrypt its password in transit. Do not forward its port to the internet.

### Wiring to ESP8266 / ESP-12F

Disconnect power and the door lock before wiring. Use GPIO numbers, not board
labels such as D1/D2. The firmware uses software SPI because hardware HSPI MISO
is GPIO 12, already used by the relay. Do not connect RC522 MISO to GPIO 12.

| RC522 pin | ESP8266 connection |
| --- | --- |
| 3.3V | Regulated 3.3 V |
| GND | Common GND |
| SCK | GPIO 14 (D5 on NodeMCU) |
| MOSI | GPIO 13 (D7 on NodeMCU) |
| MISO | GPIO 4 (D2 on NodeMCU) |
| SDA / SS | GPIO 5 (D1 on NodeMCU), SPI chip select, not I2C SDA |
| RST | 3.3 V; firmware uses RC522 software reset |
| IRQ | Unconnected |

Use 3.3 V power and logic only; never connect RC522 to 5 V. Put a 10 kOhm
pull-up between SS and 3.3 V, and 100 nF plus 10 uF decoupling near the reader.
Keep SPI wires short, ideally under 20 cm. Ensure the 3.3 V regulator can power
both ESP8266 Wi-Fi bursts and RC522. GPIO 0 reset button, GPIO 2 status LED,
GPIO 12 relay, and boot strap pins keep their existing functions. On a bare
ESP8266, retain its usual EN/reset/boot strap resistors and external relay
pull-down; these connections do not replace them.

### Build, enroll, and delete

1. Disconnect the lock; build and flash through USB using the legacy SDK:

   ```sh
   esp-lagecy
   idf.py build
   python3 tests/check_rfid.py
   python3 tests/check_ota_safety.py
   idf.py -p /dev/ttyUSB0 flash monitor
   ```

2. Look for `RC522 ready (version 91)` or `RC522 ready (version 92)` in the
   serial log. If reader detection fails, existing web/server features still
   work, but card opening is disabled. Correct wiring and restart. Some clones
   report other chip versions; firmware currently rejects those versions.

3. Provision Wi-Fi if necessary, set a panel password, save/reboot, and sign in
   through the device's LAN address as `admin`. Under **RFID cards**, enter
   `Ali's card`, choose **Enroll next card**, confirm, and present one dedicated
   Classic 1K card within 60 seconds. Keep it still until the panel reports
   successful enrollment. Enrollment itself never opens the door.

4. Remove the card fully from the RF field, then present it again. Expect one
   300 ms active-high pulse on GPIO 12 and `Authenticated card opened door` in
   the serial log. Keeping a successfully read card in the field should not
   repeatedly open the door; remove it before another scan.

5. Choose **Delete** next to the name and confirm. Access is revoked and the
   name disappears. Card presence is not needed for deletion; card contents
   are not reset. Unplug/restart the ESP8266 and verify the deleted card still
   cannot open the door.

**Enrollment changes sector 7 only:** block 28 receives the credential; trailer
31 receives random keys and transport access conditions `FF 07 80`. Blocks 29
and 30 stay untouched. Sector 0/manufacturer UID and all other sectors stay
untouched. New cards must have factory Key A `FF FF FF FF FF FF` and sector 7
transport access conditions. Never enroll payment, transit, work-access, or
other cards whose existing data/keys matter.

Keys are saved before card writes, and access is granted only after card
read-back and NVS commit succeed. Interrupted enrollment stays **pending** and
cannot open the door. Start enrollment again with the same card/name to recover;
keep other cards away during recovery. **Cancel enrollment** stops the window;
it does not restore card data or remove pending records.

Deleted records retain revoked keys internally so the same card can be
re-enrolled while its slot has not been reused. When no empty slots remain,
enrolling a different card can reuse a revoked slot and discard those old keys.
Factory reset removes all card records and keys, as well as normal configuration.
Neither deletion nor reset restores factory keys on the physical card. Once its
keys are discarded, that card cannot be enrolled again by this firmware; use a
fresh card, or restore sector 7 with an external tool and previously saved keys.
Normal OTA updates preserve card records. Card storage has its own versioned
`rfid/cards` NVS blob; existing version-5 Wi-Fi/panel config and partitions are
unchanged. Browser configuration forms and OTA/card mutation requests now
require a per-boot CSRF token; reload old panel tabs after updating. Direct API
clients must read the token from the authenticated panel and send it as
`X-Door-CSRF` for OTA/card POSTs (or `csrf` form field for configuration).

### Device acceptance tests

Keep the lock disconnected throughout these checks; reconnect only after
polarity, startup safety, and pulse timing are verified with an LED/meter/scope.

- Enroll two cards with different names. Confirm both open once per presentation,
  names survive reboot, and deleted cards remain denied after reboot.
- Present an unregistered card, a card with only a copied UID, and (using an
  external test tool) an enrolled UID with a wrong sector 7 key or wrong block
  28 credential. None may pulse GPIO 12. A full Crypto1 clone remains a known
  limitation and is not expected to be rejected.
- Hold a valid card against the reader for 10 seconds; expect one pulse. Remove
  and re-present it; expect another. Trigger a server open while scanning;
  overlapping pulses must be rejected rather than extending relay activation.
- Disconnect Wi-Fi after enrollment; local card opening should continue. Verify
  Wi-Fi/server reconnects and authenticated WebSocket opening afterward.
- Cancel an enrollment, let another expire for 60 seconds, and scan a new card;
  it must stay denied. Try empty/oversized names, malformed JSON, missing login,
  and missing `X-Door-CSRF` headers; card management must reject them.
- Interrupt power during enrollment with a disposable card. After restart,
  verify any pending card is denied; re-enroll to recover. Denial is preferable
  to accidentally granting access after an incomplete write.
- Boot with reader disconnected and with a card present. Verify no unintended
  relay pulse and continued web/server operation. Verify GPIO 0 factory reset
  revokes every card and restarts provisioning. Reset discards keys permanently.
- Recheck provisioning, relay timing, and signed OTA rejection/updates in both
  OTA slots. Watch heap/stack behavior during concurrent card scans and TLS OTA;
  these hardware checks cannot be established by host tests or compilation.

For the later hardware upgrade, PN532 alone does not fix Classic 1K security.
Use DESFire EV2/EV3 cards plus a new driver and correctly implemented AES mutual
authentication. Existing Classic credentials do not migrate into DESFire keys.
