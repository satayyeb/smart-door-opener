#include "door_web.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "door_config.h"
#include "door_wifi.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "door_web";

static const char STYLE[] =
"<style>:root{color-scheme:light}*{box-sizing:border-box}body{font:16px system-ui,-apple-system,sans-serif;background:#f4f7fb;color:#172033;margin:0}"
"main{max-width:680px;margin:0 auto;padding:32px 20px 48px}.hero{background:linear-gradient(135deg,#2563eb,#14b8a6);color:#fff;padding:28px;border-radius:20px;box-shadow:0 12px 30px #1720331c}"
"h1{margin:0 0 8px;font-size:clamp(28px,6vw,42px)}.hero p{margin:0;color:#e0f2fe}.card{background:#fff;padding:24px;margin-top:18px;border:1px solid #dbe3ef;border-radius:16px;box-shadow:0 8px 24px #1720330d}"
"label{display:block;margin:16px 0 7px;font-weight:650}input{width:100%;padding:12px 13px;border:1px solid #c7d2e2;border-radius:9px;background:#fbfdff;color:#172033;font:inherit}input:focus{outline:3px solid #bfdbfe;border-color:#2563eb}"
"button{margin-top:22px;padding:13px 19px;border:0;border-radius:9px;background:#2563eb;color:#fff;font:inherit;font-weight:700;cursor:pointer}button:hover{background:#1d4ed8}.hint{color:#52627a}.ok{color:#047857;font-weight:650}small{color:#64748b}</style>";

static esp_err_t send_error(httpd_req_t *request, const char *status, const char *message)
{
    httpd_resp_set_status(request, status);
    httpd_resp_set_type(request, "text/plain");
    return httpd_resp_send(request, message, -1);
}

static void html_escape(const char *input, char *output, size_t size)
{
    while (*input && size > 1) {
        const char *replacement = NULL;
        if (*input == '&') replacement = "&amp;";
        else if (*input == '<') replacement = "&lt;";
        else if (*input == '>') replacement = "&gt;";
        else if (*input == '\'') replacement = "&#39;";
        else if (*input == '"') replacement = "&quot;";
        if (replacement) {
            size_t n = strlen(replacement);
            if (n >= size) break;
            memcpy(output, replacement, n);
            output += n;
            size -= n;
        } else {
            *output++ = *input;
            --size;
        }
        ++input;
    }
    *output = '\0';
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = tolower((unsigned char)c);
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static void url_decode(char *value)
{
    char *read = value, *write = value;
    while (*read) {
        if (*read == '+') { *write++ = ' '; ++read; }
        else if (*read == '%' && hex_value(read[1]) >= 0 && hex_value(read[2]) >= 0) {
            *write++ = (char)(hex_value(read[1]) * 16 + hex_value(read[2]));
            read += 3;
        } else *write++ = *read++;
    }
    *write = '\0';
}

typedef struct {
    char *ssid[DOOR_WIFI_NETWORKS_MAX];
    char *wifi_password[DOOR_WIFI_NETWORKS_MAX];
    char *websocket_uri;
    char *authorization_token;
    char *password;
    char *confirmation;
} form_fields_t;

static form_fields_t parse_form(char *body)
{
    form_fields_t fields = {0};
    char *part = body;
    while (part && *part) {
        char *next = strchr(part, '&');
        if (next) *next++ = '\0';
        char *equals = strchr(part, '=');
        if (equals) {
            *equals++ = '\0';
            url_decode(part);
            url_decode(equals);
            for (int i = 0; i < DOOR_WIFI_NETWORKS_MAX; ++i) {
                char key[32];
                snprintf(key, sizeof(key), "ssid%d", i);
                if (!strcmp(part, key)) fields.ssid[i] = equals;
                snprintf(key, sizeof(key), "wifi_password%d", i);
                if (!strcmp(part, key)) fields.wifi_password[i] = equals;
            }
            if (!strcmp(part, "websocket_uri")) fields.websocket_uri = equals;
            else if (!strcmp(part, "authorization_token")) fields.authorization_token = equals;
            else if (!strcmp(part, "password")) fields.password = equals;
            else if (!strcmp(part, "confirmation")) fields.confirmation = equals;
        }
        part = next;
    }
    return fields;
}

static char *receive_form(httpd_req_t *request)
{
    if (request->content_len <= 0 || request->content_len > 2048) return NULL;
    char *body = calloc(1, request->content_len + 1);
    if (!body) return NULL;
    int received = 0;
    while (received < request->content_len) {
        int n = httpd_req_recv(request, body + received, request->content_len - received);
        if (n <= 0) { free(body); return NULL; }
        received += n;
    }
    return body;
}

static esp_err_t root_get(httpd_req_t *request)
{
    door_config_t config;
    door_config_get(&config);
    char *wifi_fields = calloc(1, 4096);
    if (!wifi_fields) return send_error(request, "500 Internal Server Error", "Out of memory");
    for (int i = 0; i < DOOR_WIFI_NETWORKS_MAX; ++i) {
        char ssid[192];
        html_escape(config.ssid[i], ssid, sizeof(ssid));
        size_t used = strlen(wifi_fields);
        snprintf(wifi_fields + used, 4096 - used,
                 "<label>Wi-Fi network %d%s</label><input name=ssid%d maxlength=32%s value='%s'><label>Password</label><input type=password name=wifi_password%d maxlength=64 placeholder='Leave blank for an open network'>",
                 i + 1, i ? " (optional)" : "", i, i ? "" : " required", ssid, i);
    }
    char uri[1024];
    html_escape(config.websocket_uri, uri, sizeof(uri));
    const char *format =
        "<!doctype html><html><head><meta name=viewport content='width=device-width,initial-scale=1'><title>Smart Door</title>%s</head>"
        "<body><main><section class=hero><h1>Smart Door</h1><p>Configure your door controller and get it online.</p></section><section class=card><p class=ok>Setup mode is active for this initialization only.</p>"
        "<form method=post action=/api/config>%s"
        "<label>WebSocket endpoint</label><input name=websocket_uri maxlength=255 required value='%s' placeholder='" DOOR_DEFAULT_WEBSOCKET_URI "'>"
        "<label>Authorization header value</label><input type=password name=authorization_token maxlength=191 placeholder='Leave blank to keep current token'>"
        "<button>Save and reboot</button></form><p class=hint><small>After saving, the setup network and this configuration page are disabled until the next factory reset.</small></p><p><small>Station: %s &middot; Firmware 3.0.0-esp8266</small></p></section></main></body></html>";
    size_t size = strlen(format) + strlen(STYLE) + strlen(wifi_fields) + strlen(uri) + 64;
    char *html = malloc(size);
    if (!html) {
        free(wifi_fields);
        return send_error(request, "500 Internal Server Error", "Out of memory");
    }
    snprintf(html, size, format, STYLE, wifi_fields, uri,
             door_wifi_station_connected() ? "connected" : "not connected");
    httpd_resp_set_type(request, "text/html");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_send(request, html, -1);
    free(html);
    free(wifi_fields);
    return err;
}

static esp_err_t config_post(httpd_req_t *request)
{
    char *body = receive_form(request);
    if (!body) return send_error(request, "400 Bad Request", "Invalid form");
    form_fields_t fields = parse_form(body);
    door_config_t old;
    door_config_get(&old);
    char ssids[DOOR_WIFI_NETWORKS_MAX][DOOR_SSID_MAX + 1] = {0};
    char passwords[DOOR_WIFI_NETWORKS_MAX][DOOR_WIFI_PASSWORD_MAX + 1] = {0};
    for (int i = 0; i < DOOR_WIFI_NETWORKS_MAX; ++i) {
        if (fields.ssid[i]) strlcpy(ssids[i], fields.ssid[i], sizeof(ssids[i]));
        if (fields.wifi_password[i]) strlcpy(passwords[i], fields.wifi_password[i], sizeof(passwords[i]));
    }
    if (fields.authorization_token && !fields.authorization_token[0]) fields.authorization_token = old.authorization_token;
    esp_err_t err = door_config_save(ssids, passwords, fields.websocket_uri,
                                     fields.authorization_token);
    free(body);
    if (err != ESP_OK) return send_error(request, "400 Bad Request", "Invalid configuration; check all field lengths and the ws:// or wss:// URI.");
    httpd_resp_set_type(request, "text/html");
    httpd_resp_send(request, "<h1>Saved</h1><p>The device is rebooting. Reconnect to the SmartDoor AP or use its new station address.</p>", -1);
    vTaskDelay(pdMS_TO_TICKS(750));
    esp_restart();
    return ESP_OK;
}

esp_err_t door_web_start(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 4096;
    httpd_handle_t server = NULL;
    esp_err_t err = httpd_start(&server, &config);
    if (err != ESP_OK) { ESP_LOGE(TAG, "HTTP server start failed: %s", esp_err_to_name(err)); return err; }
    const httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = root_get };
    const httpd_uri_t save = { .uri = "/api/config", .method = HTTP_POST, .handler = config_post };
    if ((err = httpd_register_uri_handler(server, &root)) != ESP_OK) return err;
    return httpd_register_uri_handler(server, &save);
}
