"""Run python3 tests/check_ota_remote.py; requires a C compiler."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'main/door_ota.c').read_text()
helper = source[source.index('void door_ota_run_pending_remote_update('):]
stub = r'''
#include <assert.h>
#include <stdbool.h>
#define ESP_OK 0
#define ESP_ERR_INVALID_STATE 1
#include "door_ota.h"
static bool s_remote_update_pending, paused;
static door_ota_status_t s_status;
static int checks, updates, check_error, pause_error;
static void door_ota_get_status_stub(door_ota_status_t *s) { *s = s_status; }
#define door_ota_get_status door_ota_get_status_stub
static void set_status(door_ota_state_t state, unsigned progress, const char *message) {
    (void)progress; (void)message; s_status.state = state;
}
static void door_socket_request_ota_pause(void) { paused = true; }
static int door_socket_pause_for_ota(void) { return pause_error; }
static void door_socket_resume_after_ota(void) { paused = false; }
static int check_now(void) { ++checks; s_status.state = DOOR_OTA_AVAILABLE; return check_error; }
static void update_now(void) { ++updates; s_status.state = DOOR_OTA_ERROR; }
int main(void);
'''
checks = r'''
int main(void) {
    door_ota_run_pending_remote_update();
    assert(checks == 0 && updates == 0);
    assert(door_ota_update_latest() == ESP_OK);
    assert(paused && checks == 0 && updates == 0);
    assert(door_ota_update_latest() == ESP_ERR_INVALID_STATE);
    door_ota_run_pending_remote_update();
    assert(!paused && checks == 1 && updates == 1);
    door_ota_run_pending_remote_update();
    assert(checks == 1 && updates == 1);
    check_error = -1;
    assert(door_ota_update_latest() == ESP_OK);
    door_ota_run_pending_remote_update();
    assert(!paused && checks == 2 && updates == 1 && s_status.state == DOOR_OTA_ERROR);
    pause_error = -1;
    assert(door_ota_update_latest() == ESP_OK);
    door_ota_run_pending_remote_update();
    assert(!paused && checks == 2 && updates == 1 && s_status.state == DOOR_OTA_ERROR);
}
'''
with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    (directory / 'esp_err.h').write_text('typedef int esp_err_t;\n')
    test = directory / 'check.c'
    binary = directory / 'check'
    test.write_text(stub + helper + checks)
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-I', str(directory),
                    '-I', str(root / 'main'), str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('Remote OTA deferral, duplicate rejection, and failure recovery: passed')
