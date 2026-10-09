"""Run with activated SDK: python tests/check_http_headers.py."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
sdk = Path(os.environ['IDF_PATH'])
parser = sdk / 'components/http_parser'
with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    fixed = directory / 'fixed.c'
    subprocess.run(['python3', str(root / 'tools/patch_http_client.py'),
                    str(sdk / 'components/esp_http_client/esp_http_client.c'), str(fixed)], check=True)
    source = fixed.read_text()
    callbacks = source[source.index('static int append_header('):source.index('static int http_on_headers_complete(')]
    stub = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "http_parser.h"
#define HTTP_EVENT_ON_HEADER 0
static int events;
typedef struct {
    char *current_header_key, *current_header_value, *location, *auth_header;
    bool current_header_is_value;
    struct { bool is_chunked; } *response;
    struct { char *header_key, *header_value; } event;
} esp_http_client_t;
typedef esp_http_client_t *esp_http_client_handle_t;
static void http_utils_assign_string(char **dst, const char *src, size_t len) {
    free(*dst); *dst = malloc(len + 1); assert(*dst); memcpy(*dst, src, len); (*dst)[len] = 0;
}
static int http_dispatch_event(esp_http_client_t *c, int event, void *data, int len) {
    (void)c; (void)event; (void)data; (void)len; ++events; return 0;
}
'''
    checks = r'''
static int complete(http_parser *p) { finish_header(p->data); return 0; }
int main(void) {
    char url[1200], message[1500];
    memset(url, 'x', sizeof(url) - 1); url[sizeof(url) - 1] = 0;
    int size = snprintf(message, sizeof(message), "HTTP/1.1 302 Found\r\nLocation: %s\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", url);
    http_parser_settings settings = { .on_header_field = http_on_header_field,
        .on_header_value = http_on_header_value, .on_headers_complete = complete };
    for (int chunk = 1; chunk <= size; ++chunk) {
        http_parser p; http_parser_init(&p, HTTP_RESPONSE);
        esp_http_client_t c = {0}; typeof(*c.response) response = {0}; c.response = &response;
        p.data = &c; events = 0;
        for (int offset = 0; offset < size; offset += chunk) {
            int count = size - offset < chunk ? size - offset : chunk;
            assert(http_parser_execute(&p, &settings, message + offset, count) == (size_t)count);
            assert(HTTP_PARSER_ERRNO(&p) == HPE_OK);
        }
        assert(c.location && !strcmp(c.location, url) && response.is_chunked && events == 2);
        assert(!c.current_header_key && !c.current_header_value);
        free(c.location);
    }
    char huge[4097] = {0}; char *value = NULL;
    assert(append_header(&value, huge, sizeof(huge)) == -1 && value == NULL);
}
'''
    test = directory / 'check.c'
    binary = directory / 'check'
    test.write_text(stub + callbacks + checks)
    subprocess.run(['cc', '-std=gnu99', '-Wall', '-Wextra', '-Werror', '-Wno-implicit-fallthrough', '-I', str(parser / 'include'),
                    str(test), str(parser / 'src/http_parser.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('HTTP headers: all fragmentation boundaries and size limit passed')
