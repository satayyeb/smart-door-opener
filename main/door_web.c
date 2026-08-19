#include "door_web.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "door_config.h"
#include "door_ota.h"
#include "door_wifi.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"

static const char *TAG = "door_web";

static const char STYLE[] =
"<style>:root{color-scheme:light}*{box-sizing:border-box}body{font:16px system-ui,-apple-system,sans-serif;background:#f4f7fb;color:#172033;margin:0}"
"main{max-width:720px;margin:auto;padding:32px 20px 48px}.hero{background:linear-gradient(135deg,#2563eb,#14b8a6);color:#fff;padding:28px;border-radius:20px}"
"h1{margin:0 0 8px}.hero p{margin:0}.card{background:#fff;padding:24px;margin-top:18px;border:1px solid #dbe3ef;border-radius:16px;box-shadow:0 8px 24px #1720330d}"
"label{display:block;margin:16px 0 7px;font-weight:650}input{width:100%;padding:12px;border:1px solid #c7d2e2;border-radius:9px;font:inherit}"
"button{margin-top:18px;padding:13px 19px;border:0;border-radius:9px;background:#2563eb;color:#fff;font:inherit;font-weight:700;cursor:pointer}button:disabled{opacity:.55;cursor:not-allowed}"
".secondary{background:#475569}.hint,small{color:#64748b}.ok{color:#047857;font-weight:650}.bar{height:12px;background:#e2e8f0;border-radius:8px;overflow:hidden}.bar i{display:block;height:100%;background:#14b8a6;width:0;transition:width .25s}</style>";

static esp_err_t send_error(httpd_req_t *request, const char *status, const char *message)
{
    httpd_resp_set_status(request, status);
    httpd_resp_set_type(request, "text/plain");
    return httpd_resp_send(request, message, -1);
}

static bool authorized(httpd_req_t *request)
{
    if (!door_config_is_provisioned() || !door_config_panel_password_set()) return true;
    size_t length = httpd_req_get_hdr_value_len(request, "Authorization");
    char header[192];
    if (!length || length >= sizeof(header) || httpd_req_get_hdr_value_str(request, "Authorization", header, sizeof(header)) != ESP_OK ||
        strncmp(header, "Basic ", 6)) goto denied;
    uint8_t decoded[128]; size_t decoded_length = 0;
    if (mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &decoded_length,
                              (const unsigned char *)header + 6, strlen(header + 6)) != 0) goto denied;
    decoded[decoded_length] = 0;
    char *colon = strchr((char *)decoded, ':');
    if (!colon) goto denied;
    *colon++ = 0;
    if (!strcmp((char *)decoded, DOOR_DEFAULT_USERNAME) && door_config_check_password(colon)) return true;
denied:
    httpd_resp_set_status(request, "401 Unauthorized");
    httpd_resp_set_hdr(request, "WWW-Authenticate", "Basic realm=\"Smart Door\"");
    httpd_resp_send(request, "Authentication required", -1);
    return false;
}

static void html_escape(const char *input, char *output, size_t size)
{
    while (*input && size > 1) {
        const char *replacement = *input == '&' ? "&amp;" : *input == '<' ? "&lt;" : *input == '>' ? "&gt;" :
                                  *input == '\'' ? "&#39;" : *input == '"' ? "&quot;" : NULL;
        if (replacement) { size_t n = strlen(replacement); if (n >= size) break; memcpy(output, replacement, n); output += n; size -= n; }
        else { *output++ = *input; --size; }
        ++input;
    }
    *output = 0;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = tolower((unsigned char)c); return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static void url_decode(char *value)
{
    char *read = value, *write = value;
    while (*read) {
        if (*read == '+') { *write++ = ' '; ++read; }
        else if (*read == '%' && hex_value(read[1]) >= 0 && hex_value(read[2]) >= 0) { *write++ = hex_value(read[1]) * 16 + hex_value(read[2]); read += 3; }
        else *write++ = *read++;
    }
    *write = 0;
}

typedef struct {
    char *ssid[DOOR_WIFI_NETWORKS_MAX]; char *wifi_password[DOOR_WIFI_NETWORKS_MAX];
    char *websocket_uri; char *authorization_token; char *panel_password; char *remove_panel_password;
} form_fields_t;

static form_fields_t parse_form(char *body)
{
    form_fields_t fields = {0}; char *part = body;
    while (part && *part) {
        char *next = strchr(part, '&'); if (next) *next++ = 0;
        char *equals = strchr(part, '=');
        if (equals) {
            *equals++ = 0; url_decode(part); url_decode(equals);
            for (int i = 0; i < DOOR_WIFI_NETWORKS_MAX; ++i) {
                char key[32]; snprintf(key, sizeof(key), "ssid%d", i); if (!strcmp(part, key)) fields.ssid[i] = equals;
                snprintf(key, sizeof(key), "wifi_password%d", i); if (!strcmp(part, key)) fields.wifi_password[i] = equals;
            }
            if (!strcmp(part, "websocket_uri")) fields.websocket_uri = equals;
            else if (!strcmp(part, "authorization_token")) fields.authorization_token = equals;
            else if (!strcmp(part, "panel_password")) fields.panel_password = equals;
            else if (!strcmp(part, "remove_panel_password")) fields.remove_panel_password = equals;
        }
        part = next;
    }
    return fields;
}

static char *receive_form(httpd_req_t *request)
{
    if (request->content_len <= 0 || request->content_len > 2048) return NULL;
    char *body = calloc(1, request->content_len + 1); if (!body) return NULL;
    int received = 0;
    while (received < request->content_len) { int n = httpd_req_recv(request, body + received, request->content_len - received); if (n <= 0) { free(body); return NULL; } received += n; }
    return body;
}

static esp_err_t root_get(httpd_req_t *request)
{
    if (!authorized(request)) return ESP_OK;
    door_config_t config; door_config_get(&config);
    char *wifi_fields = calloc(1, 4096); if (!wifi_fields) return send_error(request, "500 Internal Server Error", "Out of memory");
    for (int i = 0; i < DOOR_WIFI_NETWORKS_MAX; ++i) {
        char ssid[192]; html_escape(config.ssid[i], ssid, sizeof(ssid)); size_t used = strlen(wifi_fields);
        snprintf(wifi_fields + used, 4096 - used, "<label>Wi-Fi network %d%s</label><input name=ssid%d maxlength=32%s value='%s'><label>Wi-Fi password</label><input type=password name=wifi_password%d maxlength=64 placeholder='Leave blank for an open network'>",
                 i + 1, i ? " (optional)" : "", i, i ? "" : " required", ssid, i);
    }
    char uri[1024]; html_escape(config.websocket_uri, uri, sizeof(uri));
    const char *format =
        "<!doctype html><html><head><meta name=viewport content='width=device-width,initial-scale=1'><title>Smart Door</title>%s</head><body><main>"
        "<section class=hero><h1>Smart Door</h1><p>LAN configuration and signed firmware updates.</p></section><section class=card><p class=ok>%s</p>"
        "<form method=post action=/api/config>%s<label>WebSocket endpoint</label><input name=websocket_uri maxlength=255 required value='%s'>"
        "<label>Authorization header value</label><input type=password name=authorization_token maxlength=191 placeholder='Leave blank to keep current token'>"
        "<h3>Panel access</h3><label>New optional panel password</label><input type=password name=panel_password minlength=8 placeholder='Leave blank to keep current setting'>"
        "<label><input style='width:auto' type=checkbox name=remove_panel_password value=1> Remove panel password</label><button>Save and reboot</button></form>"
        "<p class=hint><small>When set, sign in as <b>admin</b>. Without a password, anyone on the LAN can change settings.</small></p></section>"
        "<section class=card><h2>Firmware update</h2><p>Installed: <b>" FIRMWARE_VERSION "</b></p><button id=check type=button>Check for firmware updates</button> "
        "<button id=install class=secondary type=button disabled>Install signed update</button><p id=otaMessage class=hint>Ready.</p><div class=bar><i id=progress></i></div></section>"
        "<p><small>Station: %s · Firmware " FIRMWARE_VERSION "</small></p></main><script>"
        "const check=document.getElementById('check'),install=document.getElementById('install'),msg=document.getElementById('otaMessage'),bar=document.getElementById('progress');"
        "async function post(p){check.disabled=true;install.disabled=true;try{await fetch(p,{method:'POST'});}catch(e){msg.textContent='Request failed: '+e}poll()}"
        "async function poll(){try{let s=await(await fetch('/api/ota/status',{cache:'no-store'})).json();msg.textContent=s.message+(s.available_version?' Version '+s.available_version+'.':'');bar.style.width=s.progress+'%%';"
        "check.disabled=['checking','downloading','verifying'].includes(s.state);install.disabled=s.state!=='available';if(['checking','downloading','verifying','ready'].includes(s.state))setTimeout(poll,700);}catch(e){msg.textContent='Status failed: '+e}}"
        "check.onclick=()=>post('/api/ota/check');install.onclick=()=>{if(confirm('Install the verified update and restart the controller?'))post('/api/ota/start')};poll();</script></body></html>";
    const char *mode = door_config_is_provisioned() ? "Setup access point is off; this panel is available on the LAN." : "Initial setup access point is open and will turn off after saving.";
    size_t size = strlen(format) + strlen(STYLE) + strlen(mode) + strlen(wifi_fields) + strlen(uri) + 128;
    char *html = malloc(size); if (!html) { free(wifi_fields); return send_error(request, "500 Internal Server Error", "Out of memory"); }
    snprintf(html, size, format, STYLE, mode, wifi_fields, uri, door_wifi_station_connected() ? "connected" : "not connected");
    httpd_resp_set_type(request, "text/html"); httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_send(request, html, -1); free(html); free(wifi_fields); return err;
}

static esp_err_t config_post(httpd_req_t *request)
{
    if (!authorized(request)) return ESP_OK;
    char *body = receive_form(request); if (!body) return send_error(request, "400 Bad Request", "Invalid form");
    form_fields_t fields = parse_form(body); door_config_t old; door_config_get(&old);
    char ssids[DOOR_WIFI_NETWORKS_MAX][DOOR_SSID_MAX + 1] = {0}, passwords[DOOR_WIFI_NETWORKS_MAX][DOOR_WIFI_PASSWORD_MAX + 1] = {0};
    for (int i = 0; i < DOOR_WIFI_NETWORKS_MAX; ++i) { if (fields.ssid[i]) strlcpy(ssids[i], fields.ssid[i], sizeof(ssids[i])); if (fields.wifi_password[i]) strlcpy(passwords[i], fields.wifi_password[i], sizeof(passwords[i])); }
    if (fields.authorization_token && !fields.authorization_token[0]) fields.authorization_token = old.authorization_token;
    esp_err_t err = door_config_save(ssids, passwords, fields.websocket_uri, fields.authorization_token);
    if (err == ESP_OK && fields.remove_panel_password) err = door_config_set_panel_password("");
    else if (err == ESP_OK && fields.panel_password && fields.panel_password[0]) err = door_config_set_panel_password(fields.panel_password);
    free(body);
    if (err != ESP_OK) return send_error(request, "400 Bad Request", "Invalid configuration or panel password (minimum 8 characters).");
    httpd_resp_set_type(request, "text/html"); httpd_resp_send(request, "<h1>Saved</h1><p>The device is rebooting. Reconnect through its LAN address.</p>", -1);
    vTaskDelay(pdMS_TO_TICKS(750)); esp_restart(); return ESP_OK;
}

static esp_err_t ota_status_get(httpd_req_t *request)
{
    if (!authorized(request)) return ESP_OK;
    door_ota_status_t status; door_ota_get_status(&status); char json[384];
    snprintf(json, sizeof(json), "{\"state\":\"%s\",\"progress\":%u,\"current_version\":\"%s\",\"available_version\":\"%s\",\"message\":\"%s\"}",
             door_ota_state_name(status.state), status.progress, status.current_version, status.available_version, status.message);
    httpd_resp_set_type(request, "application/json"); httpd_resp_set_hdr(request, "Cache-Control", "no-store"); return httpd_resp_send(request, json, -1);
}

static esp_err_t ota_check_post(httpd_req_t *request) { if (!authorized(request)) return ESP_OK; return door_ota_check() == ESP_OK ? httpd_resp_send(request, "", 0) : send_error(request, "409 Conflict", "OTA is busy"); }
static esp_err_t ota_start_post(httpd_req_t *request) { if (!authorized(request)) return ESP_OK; return door_ota_start() == ESP_OK ? httpd_resp_send(request, "", 0) : send_error(request, "409 Conflict", "No verified update is ready"); }

esp_err_t door_web_start(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG(); config.stack_size = 6144; httpd_handle_t server = NULL;
    esp_err_t err = httpd_start(&server, &config); if (err != ESP_OK) { ESP_LOGE(TAG, "HTTP server start failed: %s", esp_err_to_name(err)); return err; }
    const httpd_uri_t routes[] = {
        { .uri = "/", .method = HTTP_GET, .handler = root_get }, { .uri = "/api/config", .method = HTTP_POST, .handler = config_post },
        { .uri = "/api/ota/status", .method = HTTP_GET, .handler = ota_status_get }, { .uri = "/api/ota/check", .method = HTTP_POST, .handler = ota_check_post },
        { .uri = "/api/ota/start", .method = HTTP_POST, .handler = ota_start_post },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); ++i) if ((err = httpd_register_uri_handler(server, &routes[i])) != ESP_OK) return err;
    return ESP_OK;
}
