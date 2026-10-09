"""Run with python3 tests/check_ota_redirects.py; requires a C compiler."""

from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "main/door_ota.c").read_text()
helper = source[source.index("static int open_download("):source.index("static int download(")]
stub = r"""
#include <assert.h>
#define ESP_OK 0
#define HTTP_TRANSPORT_OVER_SSL 2
#define ESP_LOGW(...) ((void)0)
typedef struct {
    int statuses[8], index, opens, closes;
    int open_error, header_error, redirect_error, insecure;
} client_t;
typedef client_t *esp_http_client_handle_t;
static int esp_http_client_open(client_t *c, int unused) {
    (void)unused; ++c->opens; return c->open_error;
}
static int esp_http_client_fetch_headers(client_t *c) {
    return c->header_error ? -1 : 206;
}
static int esp_http_client_get_status_code(client_t *c) { return c->statuses[c->index]; }
static int esp_http_client_close(client_t *c) { ++c->closes; return -1; }
static int esp_http_client_set_redirection(client_t *c) {
    ++c->index; return c->redirect_error;
}
static int esp_http_client_get_transport_type(client_t *c) { return c->insecure ? 1 : 2; }
"""
checks = r"""
int main(void) {
    client_t direct = {.statuses = {200}};
    assert(open_download(&direct) == 206 && direct.opens == 1 && direct.closes == 0);
    client_t github = {.statuses = {302, 302, 200}};
    assert(open_download(&github) == 206 && github.opens == 3 && github.closes == 2);
    client_t codes = {.statuses = {301, 303, 307, 308, 200}};
    assert(open_download(&codes) == 206 && codes.opens == 5);
    client_t loop = {.statuses = {302, 302, 302, 302, 302, 302, 200}};
    assert(open_download(&loop) == -1 && loop.opens == 6 && loop.closes == 5);
    client_t downgrade = {.statuses = {302, 200}, .insecure = 1};
    assert(open_download(&downgrade) == -1 && downgrade.opens == 1);
    client_t bad_location = {.statuses = {302, 200}, .redirect_error = -1};
    assert(open_download(&bad_location) == -1 && bad_location.opens == 1);
    client_t rejected = {.statuses = {403}};
    assert(open_download(&rejected) == -1 && rejected.opens == 1);
    client_t tls_failure = {.open_error = -1};
    assert(open_download(&tls_failure) == -1 && tls_failure.opens == 1);
    client_t header_failure = {.header_error = 1};
    assert(open_download(&header_failure) == -1 && header_failure.opens == 1);
}
"""
with tempfile.TemporaryDirectory() as directory:
    test = Path(directory) / "check.c"
    binary = Path(directory) / "check"
    test.write_text(stub + helper + checks)
    subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", str(test), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("OTA redirects: passed")
