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
#include "mbedtls/base64.h"

static const char *TAG = "door_web";

static const char STYLE[] =
"<style>body{font:16px system-ui;background:#111827;color:#e5e7eb;margin:0}main{max-width:560px;margin:4vh auto;padding:20px}"
"form{background:#1f2937;padding:22px;border-radius:14px}label{display:block;margin:15px 0 6px}"
"input{box-sizing:border-box;width:100%;padding:11px;border-radius:7px;border:1px solid #4b5563}"
"button{margin-top:20px;padding:12px 18px;border:0;border-radius:7px;background:#dc2626;color:white;font-weight:700}"
"small{color:#9ca3af}.warn{color:#fca5a5}.ok{color:#86efac}</style>";

static esp_err_t send_error(httpd_req_t *request, const char *status, const char *message)
{
    httpd_resp_set_status(request, status);
    httpd_resp_set_type(request, "text/plain");
    return httpd_resp_send(request, message, -1);
}

static bool authenticated(httpd_req_t *request)
{
    size_t length = httpd_req_get_hdr_value_len(request, "Authorization");
    if (length < 7 || length > 256) return false;
    char *header = malloc(length + 1);
    if (!header || httpd_req_get_hdr_value_str(request, "Authorization", header, length + 1) != ESP_OK) {
        free(header);
        return false;
    }
    bool ok = false;
    if (!strncmp(header, "Basic ", 6)) {
        unsigned char decoded[192];
        size_t decoded_length = 0;
        if (mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &decoded_length,
                                  (unsigned char *)header + 6, length - 6) == 0) {
            decoded[decoded_length] = '\0';
            char *colon = strchr((char *)decoded, ':');
            ok = colon && (size_t)(colon - (char *)decoded) == strlen(DOOR_DEFAULT_USERNAME) &&
                 !strncmp((char *)decoded, DOOR_DEFAULT_USERNAME, strlen(DOOR_DEFAULT_USERNAME)) &&
                 door_config_check_password(colon + 1);
        }
    }
    free(header);
    return ok;
}

static esp_err_t demand_auth(httpd_req_t *request)
{
    httpd_resp_set_status(request, "401 Unauthorized");
    httpd_resp_set_hdr(request, "WWW-Authenticate", "Basic realm=\"Smart Door\"");
    return httpd_resp_send(request, "Authentication required", -1);
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
    char *ssid;
    char *wifi_password;
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
            if (!strcmp(part, "ssid")) fields.ssid = equals;
            else if (!strcmp(part, "wifi_password")) fields.wifi_password = equals;
            else if (!strcmp(part, "websocket_uri")) fields.websocket_uri = equals;
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

static esp_err_t password_page(httpd_req_t *request)
{
    if (!authenticated(request)) return demand_auth(request);
    const char *page =
        "<!doctype html><html><head><meta name=viewport content='width=device-width,initial-scale=1'><title>Change password</title>"
        "<style>body{font:16px system-ui;background:#111827;color:#e5e7eb;margin:0}main{max-width:560px;margin:4vh auto;padding:20px}form{background:#1f2937;padding:22px;border-radius:14px}label{display:block;margin:15px 0 6px}input{box-sizing:border-box;width:100%;padding:11px;border-radius:7px}button{margin-top:20px;padding:12px;background:#dc2626;color:white;border:0;border-radius:7px}.warn{color:#fca5a5}</style>"
        "</head><body><main><h1>Change the default password</h1><p class=warn>Configuration is locked until the default admin password is replaced.</p>"
        "<form method=post action=/api/password><label>New password</label><input type=password name=password minlength=8 required autofocus>"
        "<label>Confirm password</label><input type=password name=confirmation minlength=8 required><button>Change password</button></form>"
        "</main></body></html>";
    httpd_resp_set_type(request, "text/html");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    return httpd_resp_send(request, page, -1);
}

static esp_err_t root_get(httpd_req_t *request)
{
    if (!authenticated(request)) return demand_auth(request);
    if (door_config_must_change_password()) return password_page(request);
    door_config_t config;
    door_config_get(&config);
    char ssid[192], uri[1024];
    html_escape(config.ssid, ssid, sizeof(ssid));
    html_escape(config.websocket_uri, uri, sizeof(uri));
    const char *format =
        "<!doctype html><html><head><meta name=viewport content='width=device-width,initial-scale=1'><title>Smart Door</title>%s</head>"
        "<body><main><h1>Smart Door</h1><p class=ok>Available through the setup AP and home network.</p>"
        "<form method=post action=/api/config><label>Wi-Fi SSID</label><input name=ssid maxlength=32 required value='%s'>"
        "<label>Wi-Fi password</label><input type=password name=wifi_password maxlength=64 placeholder='Leave blank to keep current password'>"
        "<label>WebSocket endpoint</label><input name=websocket_uri maxlength=255 required value='%s' placeholder='wss://example.com/ws'>"
        "<label>Authorization header value</label><input type=password name=authorization_token maxlength=191 placeholder='Leave blank to keep current token'>"
        "<button>Save and reboot</button></form><p><small>Station: %s &middot; Firmware 3.0.0-esp8266</small></p></main></body></html>";
    size_t size = strlen(format) + strlen(STYLE) + strlen(ssid) + strlen(uri) + 64;
    char *html = malloc(size);
    if (!html) return send_error(request, "500 Internal Server Error", "Out of memory");
    snprintf(html, size, format, STYLE, ssid, uri,
             door_wifi_station_connected() ? "connected" : "not connected");
    httpd_resp_set_type(request, "text/html");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_send(request, html, -1);
    free(html);
    return err;
}

static esp_err_t password_post(httpd_req_t *request)
{
    if (!authenticated(request)) return demand_auth(request);
    if (!door_config_must_change_password()) return send_error(request, "403 Forbidden", "Password was already initialized");
    char *body = receive_form(request);
    if (!body) return send_error(request, "400 Bad Request", "Invalid form");
    form_fields_t fields = parse_form(body);
    bool matches = fields.password && fields.confirmation && !strcmp(fields.password, fields.confirmation);
    esp_err_t err = matches ? door_config_change_password(fields.password) : ESP_ERR_INVALID_ARG;
    free(body);
    if (err != ESP_OK) return send_error(request, "400 Bad Request", "Passwords must match, contain at least 8 characters, and must not be 'admin'.");
    httpd_resp_set_type(request, "text/html");
    return httpd_resp_send(request, "<h1>Password changed</h1><p>Close this browser window, reopen the configuration page, and sign in with admin and your new password.</p>", -1);
}

static esp_err_t config_post(httpd_req_t *request)
{
    if (!authenticated(request)) return demand_auth(request);
    if (door_config_must_change_password()) return send_error(request, "403 Forbidden", "Change the default password first");
    char *body = receive_form(request);
    if (!body) return send_error(request, "400 Bad Request", "Invalid form");
    form_fields_t fields = parse_form(body);
    door_config_t old;
    door_config_get(&old);
    if (fields.wifi_password && !fields.wifi_password[0]) fields.wifi_password = old.wifi_password;
    if (fields.authorization_token && !fields.authorization_token[0]) fields.authorization_token = old.authorization_token;
    esp_err_t err = door_config_save(fields.ssid, fields.wifi_password, fields.websocket_uri,
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
    const httpd_uri_t password = { .uri = "/api/password", .method = HTTP_POST, .handler = password_post };
    const httpd_uri_t save = { .uri = "/api/config", .method = HTTP_POST, .handler = config_post };
    if ((err = httpd_register_uri_handler(server, &root)) != ESP_OK) return err;
    if ((err = httpd_register_uri_handler(server, &password)) != ESP_OK) return err;
    return httpd_register_uri_handler(server, &save);
}
