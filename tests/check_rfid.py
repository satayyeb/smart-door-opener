"""Run python3 tests/check_rfid.py; host checks, no reader or relay attached."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'main/door_rfid.c').read_text()


def function(name):
    match = re.search(r'^(?:static )?\w+ ' + name + r'\(', source, re.M)
    assert match, name
    start = source.index('{', match.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end] + '\n'


types = source[source.index('typedef struct {'):source.index('static const char *TAG')]
stub = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define DOOR_RFID_MAX_CARDS 16
#define DOOR_RFID_NAME_MAX 48
#define EMPTY 0
#define PENDING 1
#define ACTIVE 2
#define REVOKED 3
#define RFID_BLOCK 28
#define RFID_TRAILER 31
#define STATUS2 8
#define ESP_OK 0
#define ESP_ERR_INVALID_ARG 1
#define ESP_ERR_INVALID_STATE 2
#define ESP_ERR_NOT_FOUND 3
#define NVS_READWRITE 1
#define portMAX_DELAY 0
#define ENROLL_TICKS 60000
#define STORE_VERSION 1
typedef int esp_err_t;
typedef int nvs_handle_t;
typedef unsigned TickType_t;
static size_t strlcpy(char *to, const char *from, size_t capacity) {
    size_t length = strlen(from);
    if (capacity) { size_t n = length < capacity - 1 ? length : capacity - 1;
        memcpy(to, from, n); to[n] = 0; }
    return length;
}
static void esp_fill_random(void *out, size_t length) { memset(out, 0x5a, length); }
static void xSemaphoreTake(int mutex, int wait) { (void)mutex; (void)wait; }
static void xSemaphoreGive(int mutex) { (void)mutex; }
static unsigned xTaskGetTickCount(void) { return 10; }
static bool panel_password = true, provisioned = true;
static bool door_config_panel_password_set(void) { return panel_password; }
static bool door_config_is_provisioned(void) { return provisioned; }
'''
globals_ = r'''
static store_t s_store;
static int s_mutex = 1;
static bool s_ready = true, s_enrolling;
static TickType_t s_enroll_start;
static char s_name[DOOR_RFID_NAME_MAX + 1] = "Ali's card";
static char s_message[128];
static const uint8_t DEFAULT_KEY[6] = {255,255,255,255,255,255};
static uint8_t physical_uid[7] = {1,2,3,4};
static uint8_t physical_key[6], physical_secret[16];
static bool auth_ok = true, read_ok = true, trailer_ok = true;
static unsigned writes, commits, fail_commit, select_step;
static store_t staged, disk;
static int nvs_open(const char *name, int mode, nvs_handle_t *h) {
    assert(!strcmp(name, "rfid") && mode == NVS_READWRITE); *h = 1; return ESP_OK;
}
static int nvs_set_blob(nvs_handle_t h, const char *key, const void *blob, size_t length) {
    assert(h == 1 && !strcmp(key, "cards") && length == sizeof(store_t));
    memcpy(&staged, blob, length); return ESP_OK;
}
static int nvs_commit(nvs_handle_t h) {
    assert(h == 1); if (++commits == fail_commit) return 9;
    disk = staged; return ESP_OK;
}
static void nvs_close(nvs_handle_t h) { assert(h == 1); }
static bool authenticate(const uint8_t uid[7], uint8_t length, const uint8_t key[6]) {
    return auth_ok && length == 4 && !memcmp(uid, physical_uid, 4) && !memcmp(key, physical_key, 6);
}
static bool read_block(uint8_t block, uint8_t data[16]) {
    assert(block == RFID_BLOCK || block == RFID_TRAILER);
    if (!read_ok) return false;
    memset(data, 0, 16);
    if (block == RFID_BLOCK) memcpy(data, physical_secret, 16);
    else { data[6] = 0xff; data[7] = 7; data[8] = 0x80; }
    return true;
}
static bool write_block(uint8_t block, const uint8_t data[16]) {
    assert(block == 28 || block == 31); ++writes;
    if (block == 28) memcpy(physical_secret, data, 16);
    else { if (!trailer_ok) return false; memcpy(physical_key, data, 6); }
    return true;
}
static void reg_write(uint8_t reg, uint8_t value) { (void)reg; (void)value; }
static uint8_t reg_read(uint8_t reg) { (void)reg; return 0; }
static void finish_card(void) {}
static void reset_field(void) { select_step = 0; }
static unsigned cascade_mode;
static bool bad_bcc, bad_crc, bad_bits, bad_sak;
'''
exchange = r'''
static bool exchange(uint8_t command, const uint8_t *tx, size_t tx_length,
                     unsigned tx_bits, uint8_t *rx, size_t *length, unsigned *bits) {
    assert(command == 0x0c); *bits = bad_bits ? 1 : 0;
    if (select_step++ == 0) {
        assert(tx_length == 1 && tx[0] == 0x26 && tx_bits == 7);
        rx[0] = 4; rx[1] = 0; *length = 2;
    } else if (tx_length == 2) {
        assert(*length >= 5 && tx[1] == 0x20);
        if (cascade_mode && tx[0] == 0x93) { rx[0] = 0x88; memcpy(rx + 1, physical_uid, 3); }
        else memcpy(rx, physical_uid + (cascade_mode ? 3 : 0), 4);
        rx[4] = rx[0] ^ rx[1] ^ rx[2] ^ rx[3];
        if (bad_bcc) rx[4] ^= 1;
        *length = 5;
    } else {
        assert(tx_length == 9 && crc_valid(tx, tx_length));
        rx[0] = bad_sak ? 0x18 : (cascade_mode && tx[0] == 0x93 ? 4 : 8);
        crc_a(rx, 1, rx + 1);
        if (bad_crc) rx[1] ^= 1;
        *length = 3;
    }
    return true;
}
'''
checks = r'''
static void reset(void) {
    memset(&s_store, 0, sizeof(s_store)); s_store.version = STORE_VERSION;
    memset(physical_key, 255, sizeof(physical_key)); memset(physical_secret, 0, 16);
    writes = commits = fail_commit = select_step = 0;
    auth_ok = read_ok = trailer_ok = panel_password = provisioned = s_ready = true;
    s_enrolling = bad_bcc = bad_crc = bad_bits = bad_sak = false; cascade_mode = 0;
    for (unsigned i = 0; i < 7; ++i) physical_uid[i] = i + 1;
}
int main(void) {
    uint8_t crc[2], halt[] = {0x50,0,0x57,0xcd};
    crc_a(halt, 2, crc); assert(crc[0] == 0x57 && crc[1] == 0xcd);
    assert(crc_valid(halt, 4)); halt[3] ^= 1; assert(!crc_valid(halt, 4));
    assert(!crc_valid(halt, 1));
    uint8_t uid[7], length;
    reset(); assert(select_card(uid, &length) && length == 4 && !memcmp(uid, physical_uid, 4));
    reset(); cascade_mode = 1; assert(select_card(uid, &length) && length == 7 && !memcmp(uid, physical_uid, 7));
    reset(); bad_bcc = true; assert(!select_card(uid, &length));
    reset(); bad_crc = true; assert(!select_card(uid, &length));
    reset(); bad_bits = true; assert(!select_card(uid, &length));
    reset(); bad_sak = true; assert(!select_card(uid, &length));

    reset(); fail_commit = 1; enroll_card(physical_uid, 4);
    assert(writes == 0 && s_store.cards[0].state == EMPTY);
    reset(); trailer_ok = false; enroll_card(physical_uid, 4);
    assert(writes == 2 && s_store.cards[0].state == PENDING);
    assert(!card_authorized(physical_uid, 4));
    trailer_ok = true; enroll_card(physical_uid, 4);
    assert(s_store.cards[0].state == ACTIVE && disk.cards[0].state == ACTIVE);
    assert(card_authorized(physical_uid, 4));
    auth_ok = false; assert(!card_authorized(physical_uid, 4)); auth_ok = true;
    read_ok = false; assert(!card_authorized(physical_uid, 4)); read_ok = true;
    physical_secret[0] ^= 1; assert(!card_authorized(physical_uid, 4)); physical_secret[0] ^= 1;
    uint8_t unknown[7] = {9,9,9,9}; assert(!card_authorized(unknown, 4));
    assert(!card_authorized(physical_uid, 3));
    fail_commit = commits + 1; assert(door_rfid_delete(1) != ESP_OK);
    assert(card_authorized(physical_uid, 4));
    fail_commit = 0; assert(door_rfid_delete(1) == ESP_OK);
    assert(s_store.cards[0].state == REVOKED && !card_authorized(physical_uid, 4));
    s_store = disk; assert(!card_authorized(physical_uid, 4)); /* reboot */
    enroll_card(physical_uid, 4); assert(card_authorized(physical_uid, 4));
    assert(door_rfid_delete(0) == ESP_ERR_INVALID_ARG && door_rfid_delete(17) == ESP_ERR_INVALID_ARG);
    reset(); fail_commit = 2; enroll_card(physical_uid, 4);
    assert(s_store.cards[0].state == PENDING && !card_authorized(physical_uid, 4));
    fail_commit = 0; enroll_card(physical_uid, 4);
    assert(s_store.cards[0].state == ACTIVE && card_authorized(physical_uid, 4));
    reset(); auth_ok = false; enroll_card(physical_uid, 4); assert(writes == 0);

    reset(); assert(door_rfid_enroll("") == ESP_ERR_INVALID_ARG);
    assert(door_rfid_enroll("   ") == ESP_ERR_INVALID_ARG);
    assert(door_rfid_enroll("bad\nname") == ESP_ERR_INVALID_ARG);
    char long_name[50]; memset(long_name, 'a', 49); long_name[49] = 0;
    assert(door_rfid_enroll(long_name) == ESP_ERR_INVALID_ARG);
    panel_password = false; assert(door_rfid_enroll("Ali") == ESP_ERR_INVALID_STATE);
    panel_password = true; provisioned = false; assert(door_rfid_enroll("Ali") == ESP_ERR_INVALID_STATE);
    provisioned = true; s_ready = false; assert(door_rfid_enroll("Ali") == ESP_ERR_INVALID_STATE);
    s_ready = true; assert(door_rfid_enroll("Ali") == ESP_OK && s_enrolling);
    assert(door_rfid_enroll("Other") == ESP_ERR_INVALID_STATE);
    assert(door_rfid_cancel() == ESP_OK && !s_enrolling);
    reset(); for (unsigned i = 0; i < 16; ++i) { s_store.cards[i].state = ACTIVE; s_store.cards[i].uid_length = 4; }
    enroll_card(physical_uid, 4); assert(writes == 0 && strstr(s_message, "full"));
    puts("RFID: CRC, selection, credentials, enrollment recovery, revocation, storage failures, and bounds passed");
}
'''
with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    test = directory / 'check.c'
    binary = directory / 'check'
    test.write_text(stub + types + globals_ + function('crc_a') + function('crc_valid') + exchange +
                    function('select_card') + function('persist') + function('same_uid') +
                    function('credential_matches') + function('card_authorized') + function('enroll_card') +
                    function('door_rfid_enroll') + function('door_rfid_cancel') + function('door_rfid_delete') + checks)
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# Exercise actual HTTP handlers against the SDK's legacy JSON parser.
import os
sdk = Path(os.environ.get('IDF_PATH', str(Path.home() / 'esp/ESP8266_RTOS_SDK')))
web_source = (root / 'main/door_web.c').read_text()


def web_function(name):
    global source
    original = source
    source = web_source
    try:
        return function(name)
    finally:
        source = original


web_stub = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#define ESP_OK 0
#define ESP_ERR_INVALID_ARG 1
#define ESP_ERR_INVALID_STATE 2
#define ESP_ERR_INVALID_SIZE 4
#define DOOR_RFID_MAX_CARDS 16
#define DOOR_RFID_NAME_MAX 48
typedef int esp_err_t;
typedef struct { const char *uri; int content_len; const char *body; } httpd_req_t;
typedef struct { unsigned id; bool pending; char name[49]; } door_rfid_card_t;
typedef struct { bool ready, enrolling; char message[128]; unsigned count; door_rfid_card_t cards[16]; } door_rfid_status_t;
static char s_csrf[33] = "0123456789abcdef0123456789abcdef";
static const char *header_token, *header_content = "application/json";
static bool password = true, provisioned = true, auth = true;
static unsigned operations;
static char status[64], response[16384];
static unsigned card_count = 1, allocation_attempts, chunks, fail_chunk;
static bool worst_case, ended;
static void *deny_alloc(size_t size) { (void)size; ++allocation_attempts; return NULL; }
static int httpd_resp_send_chunk(httpd_req_t *r, const char *body, int length) {
    (void)r;
    if (++chunks == fail_chunk) return 9;
    if (length == 0) { ended = true; return ESP_OK; }
    size_t used = strlen(response), count = length < 0 ? strlen(body) : (size_t)length;
    assert(used + count < sizeof(response));
    memcpy(response + used, body, count); response[used + count] = 0;
    return ESP_OK;
}
static size_t httpd_req_get_hdr_value_len(httpd_req_t *r, const char *name) {
    (void)r; assert(!strcmp(name, "X-Door-CSRF")); return header_token ? strlen(header_token) : 0;
}
static int httpd_req_get_hdr_value_str(httpd_req_t *r, const char *name, char *out, size_t length) {
    (void)r; const char *value = !strcmp(name, "Content-Type") ? header_content : header_token;
    if (!value || strlen(value) >= length) return 9;
    strcpy(out, value); return ESP_OK;
}
static int httpd_resp_send(httpd_req_t *r, const char *body, int length) {
    (void)r; (void)length; snprintf(response, sizeof(response), "%s", body); return 0;
}
static int httpd_resp_set_type(httpd_req_t *r, const char *type) { (void)r; (void)type; return 0; }
static int httpd_resp_set_hdr(httpd_req_t *r, const char *key, const char *value) { (void)r; (void)key; (void)value; return 0; }
static int send_error(httpd_req_t *r, const char *code, const char *message) {
    snprintf(status, sizeof(status), "%s", code); return httpd_resp_send(r, message, -1);
}
static bool authorized(httpd_req_t *r) { if (!auth) send_error(r, "401 Unauthorized", "Login"); return auth; }
static bool door_config_is_provisioned(void) { return provisioned; }
static bool door_config_panel_password_set(void) { return password; }
static char *receive_form(httpd_req_t *r) {
    char *out = calloc(1, r->content_len + 1); assert(out); memcpy(out, r->body, r->content_len); return out;
}
static int door_rfid_enroll(const char *name) { assert(!strcmp(name, "Ali's card")); ++operations; return 0; }
static int door_rfid_delete(unsigned id) { assert(id == 1); ++operations; return 0; }
static int door_rfid_cancel(void) { ++operations; return 0; }
static void door_rfid_get_status(door_rfid_status_t *out) {
    memset(out, 0, sizeof(*out)); out->ready = true; out->count = card_count;
    strcpy(out->message, "Ready");
    if (worst_case) memset(out->message, 1, sizeof(out->message) - 1);
    for (unsigned i = 0; i < card_count; ++i) {
        out->cards[i].id = i + 1; out->cards[i].pending = i % 2;
        strcpy(out->cards[i].name, "Ali's <script>\"card\"");
        if (worst_case) memset(out->cards[i].name, 1, DOOR_RFID_NAME_MAX);
    }
}
'''
web_checks = r'''
static void request(const char *path, const char *body) {
    httpd_req_t r = {.uri = path, .content_len = (int)strlen(body), .body = body};
    status[0] = 0; response[0] = 0; rfid_post(&r);
}
int main(void) {
    header_token = s_csrf;
    request("/api/rfid/enroll", "{\"name\":\"Ali's card\"}"); assert(operations == 1 && !status[0]);
    header_token = NULL; request("/api/rfid/cancel", "{}"); assert(operations == 1 && strstr(status, "403"));
    header_token = "wrong"; request("/api/rfid/cancel", "{}"); assert(operations == 1 && strstr(status, "403"));
    header_token = s_csrf; password = false; request("/api/rfid/cancel", "{}"); assert(operations == 1 && strstr(status, "403"));
    password = true; provisioned = false; request("/api/rfid/cancel", "{}"); assert(operations == 1 && strstr(status, "403"));
    provisioned = true; auth = false; request("/api/rfid/cancel", "{}"); assert(operations == 1 && strstr(status, "401"));
    auth = true;
    const char *bad[] = {"{", "[]", "{} garbage", "{\"id\":0}", "{\"id\":17}", "{\"id\":1.5}", "{\"id\":\"1\"}", "{\"id\":1e300}", "{\"id\":true}"};
    for (unsigned i = 0; i < sizeof(bad)/sizeof(*bad); ++i) {
        request("/api/rfid/delete", bad[i]); assert(operations == 1 && strstr(status, "400"));
    }
    header_content = "text/plain"; request("/api/rfid/cancel", "{}"); assert(operations == 1 && strstr(status, "400"));
    header_content = "application/json";
    request("/api/rfid/enroll?unexpected=1", "{}"); assert(operations == 1 && strstr(status, "400"));
    char oversized[258]; memset(oversized, ' ', 257); oversized[257] = 0;
    request("/api/rfid/cancel", oversized); assert(operations == 1 && strstr(status, "400"));
    const char nul[] = {'{','}',0,'{','}'};
    httpd_req_t r = {.uri = "/api/rfid/cancel", .body = nul, .content_len = sizeof(nul)};
    rfid_post(&r); assert(operations == 1 && strstr(status, "400"));
    request("/api/rfid/delete", "{\"id\":1}"); assert(operations == 2 && !status[0]);
    request("/api/rfid/cancel", "{}"); assert(operations == 3 && !status[0]);
    cJSON_Hooks hooks = {.malloc_fn = deny_alloc, .free_fn = free};
    for (unsigned count = 0; count <= 16; ++count) {
        for (unsigned controls = 0; controls < 2; ++controls) {
            card_count = count; worst_case = controls; status[0] = response[0] = 0;
            ended = false; chunks = allocation_attempts = 0;
            cJSON_InitHooks(&hooks);
            assert(rfid_status_get(&r) == ESP_OK && ended && !status[0] && allocation_attempts == 0);
            cJSON_InitHooks(NULL);
            cJSON *json = cJSON_Parse(response); assert(json);
            assert(cJSON_IsTrue(cJSON_GetObjectItem(json, "ready")));
            assert(cJSON_IsFalse(cJSON_GetObjectItem(json, "enrolling")));
            cJSON *message = cJSON_GetObjectItem(json, "message");
            assert(strlen(message->valuestring) == (controls ? 127 : 5));
            cJSON *cards = cJSON_GetObjectItem(json, "cards"); assert(cJSON_GetArraySize(cards) == (int)count);
            for (unsigned i = 0; i < count; ++i) {
                cJSON *card = cJSON_GetArrayItem(cards, i);
                const char *name = cJSON_GetObjectItem(card, "name")->valuestring;
                if (controls) { assert(strlen(name) == 48); for (unsigned j = 0; j < 48; ++j) assert(name[j] == 1); }
                else assert(!strcmp(name, "Ali's <script>\"card\""));
                assert(cJSON_GetObjectItem(card, "id")->valueint == (int)i + 1);
                assert(cJSON_IsTrue(cJSON_GetObjectItem(card, "pending")) == (int)(i % 2));
                assert(!cJSON_GetObjectItem(card, "key") && !cJSON_GetObjectItem(card, "secret") && !cJSON_GetObjectItem(card, "uid"));
            }
            cJSON_Delete(json);
        }
    }
    response[0] = 0; chunks = 0; fail_chunk = 2; ended = false;
    assert(rfid_status_get(&r) == 9 && chunks == 2 && !ended);
    puts("RFID status: 0-16 cards, denied JSON allocations, worst-case escaping, and send errors passed");
    puts("RFID web: password, login, CSRF, JSON bounds, deletion IDs, and safe status output passed");
}
'''
with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    test = directory / 'web.c'
    binary = directory / 'web'
    test.write_text(web_stub + web_function('csrf_authorized') + web_function('rfid_authorized') +
                    web_function('send_json_string') + web_function('rfid_status_get') + web_function('rfid_post') + web_checks)
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-I', str(sdk / 'components/json/cJSON'),
                    str(test), str(sdk / 'components/json/cJSON/cJSON.c'), '-lm', '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# Check syntax of the embedded page script after C string decoding/formatting.
import ast
format_section = web_source[web_source.index('    const char *format ='):web_source.index('    const char *mode =')]
html = ''.join(ast.literal_eval(string) for string in re.findall(r'"(?:[^"\\]|\\.)*"', format_section))
html = html.replace('%s', 'test').replace('%%', '%')
script = html.split('<script>', 1)[1].split('</script>', 1)[0]
subprocess.run(['node', '--check'], input=script, text=True, check=True)
print('Panel JavaScript syntax: passed')

# Check relay overlap and fail-safe behavior with competing callers.
control = (root / 'main/door_control.c').read_text()
relay_stub = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#define ESP_OK 0
#define ESP_ERR_INVALID_STATE 1
#define ESP_ERROR_CHECK(call) assert((call) == ESP_OK)
#define RELAY_GPIO 12
#define RELAY_ACTIVE_LEVEL 1
#define RELAY_PULSE_US (300 * 1000)
#define portENTER_CRITICAL() (++critical)
#define portEXIT_CRITICAL() (--critical)
typedef int esp_err_t;
static int s_relay_timer = 1, critical, level, timer_error, gpio_error;
static bool s_active, compete;
static int door_control_open(void);
static int gpio_set_level(int gpio, int value) {
    assert(gpio == 12); level = value;
    if (compete && value) { compete = false; assert(door_control_open() == ESP_ERR_INVALID_STATE); }
    return value ? gpio_error : ESP_OK;
}
static int esp_timer_start_once(int timer, int interval) {
    assert(timer == 1 && interval == 300000); return timer_error;
}
'''
relay_off = control[control.index('static void relay_off('):control.index('esp_err_t door_control_init(')]
relay_open = control[control.index('esp_err_t door_control_open('):]
relay_checks = r'''
int main(void) {
    compete = true; assert(door_control_open() == ESP_OK && level == 1 && s_active && critical == 0);
    assert(door_control_open() == ESP_ERR_INVALID_STATE && level == 1);
    relay_off(NULL); assert(level == 0 && !s_active && critical == 0);
    timer_error = 9; assert(door_control_open() == 9 && level == 0 && !s_active);
    timer_error = 0; gpio_error = 8; assert(door_control_open() == 8 && level == 0 && !s_active);
    puts("Relay: overlapping callers rejected, 300 ms timer retained, errors deactivate output");
}
'''
with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    test = directory / 'relay.c'
    binary = directory / 'relay'
    test.write_text(relay_stub + relay_off + relay_open + relay_checks)
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
