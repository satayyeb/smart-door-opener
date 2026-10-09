"""Run python3 tests/check_ota_ranges.py; requires a C compiler."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'main/door_ota.c').read_text()
start = source.index('typedef struct {', source.index('static bool image_mapping_valid('))
helper = source[start:source.index('static void update_now(')]
stub = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#define ESP_OK 0
#define HTTP_EVENT_ON_HEADER 1
#define OTA_RANGE_SIZE 4096
typedef int esp_err_t;
typedef struct { int event_id; char *header_key, *header_value; void *user_data; } esp_http_client_event_t;
typedef struct { int status, length, error; char *response; void *range; unsigned start, end; } client_t;
typedef client_t *esp_http_client_handle_t;
static int esp_http_client_set_header(client_t *c, const char *key, const char *value) {
    assert(!strcmp(key, "Range")); assert(sscanf(value, "bytes=%u-%u", &c->start, &c->end) == 2); return c->error;
}
static int esp_http_client_get_status_code(client_t *c) { return c->status; }
static int open_download(client_t *c);
'''
checks = r'''
static int open_download(client_t *c) {
    if (c->response) {
        esp_http_client_event_t e = { HTTP_EVENT_ON_HEADER, "Content-Range", c->response, c->range };
        range_header(&e);
    }
    return c->length;
}
int main(void) {
    download_range_t range = {0};
    client_t c = { .status = 206, .length = 4096, .response = "bytes 0-4095/5000", .range = &range };
    assert(open_range(&c, &range, 0, 0, 10000) == 4096);
    assert(c.start == 0 && c.end == 4095 && range.total == 5000);
    c.response = "bytes 4096-4999/5000"; c.length = 904;
    assert(open_range(&c, &range, 4096, 5000, 10000) == 904);
    c.response = "bytes 4096-4999/6000";
    assert(open_range(&c, &range, 4096, 5000, 10000) == -1);
    c.response = "bytes 0-4095/5000"; c.length = 4096;
    assert(open_range(&c, &range, 4096, 5000, 10000) == -1);
    assert(open_range(&c, &range, 0, 0, 4999) == -1);
    c.length = 4095;
    assert(open_range(&c, &range, 0, 0, 10000) == -1);
    c.length = 4096; c.status = 200;
    assert(open_range(&c, &range, 0, 0, 10000) == -1);
    c.status = 206;
    const char *bad[] = {"bytes */5000", "bytes 4095-0/5000", "bytes 0-4095/4095",
        "bytes 0-4095/5000junk", "bytes 0-9999/10000", "bytes 0-4094/5000"};
    for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) {
        c.response = (char *)bad[i];
        assert(open_range(&c, &range, 0, 0, 10000) == -1);
    }
    c.response = NULL;
    assert(open_range(&c, &range, 0, 0, 10000) == -1);
    c.error = -1;
    assert(open_range(&c, &range, 0, 0, 10000) == -1);
}
'''
with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    test = directory / 'check.c'; binary = directory / 'check'
    test.write_text(stub + helper + checks)
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('OTA ranges: exact offsets, size limits, changed totals, and malformed responses passed')
