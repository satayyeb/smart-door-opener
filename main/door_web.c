#include "door_web.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "door_config.h"
#include "door_ota.h"
#include "door_rfid.h"
#include "cJSON.h"
#include "door_wifi.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"

static const char *TAG = "door_web";
static char s_csrf[33];

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

static bool csrf_authorized(httpd_req_t *request)
{
    char token[sizeof(s_csrf)];
    return httpd_req_get_hdr_value_len(request, "X-Door-CSRF") == sizeof(s_csrf) - 1 &&
           httpd_req_get_hdr_value_str(request, "X-Door-CSRF", token, sizeof(token)) == ESP_OK &&
           !strcmp(token, s_csrf);
}

static bool rfid_authorized(httpd_req_t *request, bool mutation)
{
    if (!door_config_is_provisioned() || !door_config_panel_password_set()) {
        send_error(request, "403 Forbidden", "Provision device and set panel password before managing cards");
        return false;
    }
    if (!authorized(request)) return false;
    if (mutation && !csrf_authorized(request)) {
        send_error(request, "403 Forbidden", "Invalid request token; reload panel");
        return false;
    }
    return true;
}

static const char RFID_PANEL[] =
"<section class=card><h2>RFID cards</h2><p>Classic 1K cards can be cloned despite custom keys. Use dedicated cards: enrollment overwrites sector 7 block 28 and trailer 31.</p>"
"<p>Set panel password before managing cards. Card scans require no PIN or phone.</p>"
"<label for=cardName>Card name</label><input id=cardName maxlength=48 placeholder=\"Ali's card\">"
"<button id=enrollCard type=button>Enroll next card</button> <button id=cancelCard type=button class=secondary>Cancel enrollment</button>"
"<p id=rfidMessage role=status>Loading reader status...</p><ul id=cardList></ul></section>";

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
        else if (*read == '%' && read[1] && read[2] && hex_value(read[1]) >= 0 && hex_value(read[2]) >= 0) { *write++ = hex_value(read[1]) * 16 + hex_value(read[2]); read += 3; }
        else *write++ = *read++;
    }
    *write = 0;
}

typedef struct {
    char *ssid[DOOR_WIFI_NETWORKS_MAX]; char *wifi_password[DOOR_WIFI_NETWORKS_MAX];
    char *clear_wifi_password[DOOR_WIFI_NETWORKS_MAX];
    char *websocket_uri; char *authorization_token; char *panel_password; char *remove_panel_password; char *csrf;
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
                snprintf(key, sizeof(key), "clear_wifi_password%d", i); if (!strcmp(part, key)) fields.clear_wifi_password[i] = equals;
            }
            if (!strcmp(part, "csrf")) fields.csrf = equals;
            else if (!strcmp(part, "websocket_uri")) fields.websocket_uri = equals;
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
        snprintf(wifi_fields + used, 4096 - used, "<label>Wi-Fi network %d%s</label><input name=ssid%d maxlength=32%s value='%s'><label>Wi-Fi password</label><input type=password name=wifi_password%d maxlength=64 placeholder='Leave blank to keep saved password'><label><input style='width:auto' type=checkbox name=clear_wifi_password%d value=1> Clear saved password (open network)</label>",
                 i + 1, i ? " (optional)" : "", i, i ? "" : " required", ssid, i, i);
    }
    char uri[1024]; html_escape(config.websocket_uri, uri, sizeof(uri));
    const char *format =
        "<!doctype html><html><head><meta name=viewport content='width=device-width,initial-scale=1'><title>Smart Door</title>%s</head><body><main>"
        "<section class=hero><h1>Smart Door</h1><p>LAN configuration and signed firmware updates.</p></section><section class=card><p class=ok>%s</p>"
        "<form method=post action=/api/config><input type=hidden name=csrf value='%s'>%s<label>WebSocket endpoint</label><input name=websocket_uri maxlength=255 required value='%s'>"
        "<label>Device token or full Authorization header value</label><input type=password name=authorization_token maxlength=191 placeholder='Leave blank to keep current token'>"
        "<h3>Panel access</h3><label>New optional panel password</label><input type=password name=panel_password minlength=8 placeholder='Leave blank to keep current setting'>"
        "<label><input style='width:auto' type=checkbox name=remove_panel_password value=1> Remove panel password</label><button>Save and reboot</button></form>"
        "<p class=hint><small>When set, sign in as <b>admin</b>. Without a password, anyone on the LAN can change settings.</small></p></section>"
        "<section class=card><h2>Firmware update</h2><p>Installed: <b>" FIRMWARE_VERSION "</b></p><button id=check type=button>Check for firmware updates</button> "
        "<button id=install class=secondary type=button disabled>Install signed update</button><p id=otaMessage class=hint>Ready.</p><div class=bar><i id=progress></i></div></section>"
        "%s<p><small>Station: %s | Firmware " FIRMWARE_VERSION " | Designed by Sayyed Ali Tayyeb</small></p></main><script>"
        "const csrf='%s';const check=document.getElementById('check'),install=document.getElementById('install'),msg=document.getElementById('otaMessage'),bar=document.getElementById('progress');"
        "async function post(p){check.disabled=true;install.disabled=true;try{let r=await fetch(p,{method:'POST',headers:{'X-Door-CSRF':csrf}});if(!r.ok)throw Error('HTTP '+r.status);}catch(e){msg.textContent='Request failed: '+e}poll()}"
        "async function poll(){try{let r=await fetch('/api/ota/status',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);let text=await r.text();if(!text)throw Error('Empty status response');let s=JSON.parse(text);msg.textContent=s.message+(s.available_version?' Version '+s.available_version+'.':'');bar.style.width=s.progress+'%%';"
        "check.disabled=['checking','downloading','verifying'].includes(s.state);install.disabled=s.state!=='available';if(['checking','downloading','verifying','ready'].includes(s.state))setTimeout(poll,700);}catch(e){msg.textContent='Controller unavailable; retrying. '+e.message;setTimeout(poll,2000)}}"
        "check.onclick=()=>post('/api/ota/check');install.onclick=()=>{if(confirm('Install the verified update and restart the controller?'))post('/api/ota/start')};poll();"
        "const cardMsg=document.getElementById('rfidMessage'),cardList=document.getElementById('cardList'),enroll=document.getElementById('enrollCard'),cancel=document.getElementById('cancelCard');"
        "async function cardPost(path,data={}){try{let r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Door-CSRF':csrf},body:JSON.stringify(data)});if(!r.ok)throw Error(await r.text());await cardsPoll(false)}catch(e){cardMsg.textContent=e.message}}"
        "async function cardsPoll(repeat=true){try{let r=await fetch('/api/rfid/status',{cache:'no-store'});if(!r.ok)throw Error(await r.text());let s=await r.json();cardMsg.textContent=s.message;enroll.disabled=!s.ready||s.enrolling;cancel.disabled=!s.enrolling;cardList.replaceChildren();"
        "for(let c of s.cards){let li=document.createElement('li'),b=document.createElement('button');li.append(document.createTextNode(c.name+(c.pending?' (pending; no access)':'')+' '));b.type='button';b.className='secondary';b.textContent='Delete';b.onclick=()=>{if(confirm('Revoke access for '+c.name+'?'))cardPost('/api/rfid/delete',{id:c.id})};li.append(b);cardList.append(li)}}"
        "catch(e){cardMsg.textContent=e.message;enroll.disabled=true;cancel.disabled=true}if(repeat)setTimeout(cardsPoll,1500)}"
        "enroll.onclick=()=>{let name=document.getElementById('cardName').value.trim();if(!name){cardMsg.textContent='Enter card name';return}if(confirm('Overwrite sector 7 on next card? Use a dedicated card.'))cardPost('/api/rfid/enroll',{name})};cancel.onclick=()=>cardPost('/api/rfid/cancel');cardsPoll();</script></body></html>";
    const char *mode = door_config_is_provisioned() ? "Setup access point is off; this panel is available on the LAN." : "Initial setup access point is open and will turn off after saving.";
    size_t size = strlen(format) + strlen(STYLE) + strlen(mode) + strlen(wifi_fields) + strlen(uri) + strlen(RFID_PANEL) + sizeof(s_csrf) * 2 + 128;
    char *html = malloc(size); if (!html) { free(wifi_fields); return send_error(request, "500 Internal Server Error", "Out of memory"); }
    snprintf(html, size, format, STYLE, mode, s_csrf, wifi_fields, uri, RFID_PANEL, door_wifi_station_connected() ? "connected" : "not connected", s_csrf);
    httpd_resp_set_type(request, "text/html"); httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_send(request, html, -1); free(html); free(wifi_fields); return err;
}

static esp_err_t config_post(httpd_req_t *request)
{
    if (!authorized(request)) return ESP_OK;
    char *body = receive_form(request); if (!body) return send_error(request, "400 Bad Request", "Invalid form");
    form_fields_t fields = parse_form(body);
    if (!fields.csrf || strcmp(fields.csrf, s_csrf)) { free(body); return send_error(request, "403 Forbidden", "Invalid request token; reload panel"); }
    door_config_t old; door_config_get(&old);
    char ssids[DOOR_WIFI_NETWORKS_MAX][DOOR_SSID_MAX + 1] = {0}, passwords[DOOR_WIFI_NETWORKS_MAX][DOOR_WIFI_PASSWORD_MAX + 1] = {0};
    for (int i = 0; i < DOOR_WIFI_NETWORKS_MAX; ++i) {
        if (fields.ssid[i]) strlcpy(ssids[i], fields.ssid[i], sizeof(ssids[i]));
        if (fields.wifi_password[i] && fields.wifi_password[i][0])
            strlcpy(passwords[i], fields.wifi_password[i], sizeof(passwords[i]));
        else if (!fields.clear_wifi_password[i] && !strcmp(ssids[i], old.ssid[i]))
            strlcpy(passwords[i], old.wifi_password[i], sizeof(passwords[i]));
    }
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

static esp_err_t ota_check_post(httpd_req_t *request) { if (!authorized(request)) return ESP_OK; if (!csrf_authorized(request)) return send_error(request, "403 Forbidden", "Invalid request token"); return door_ota_check() == ESP_OK ? httpd_resp_send(request, "", 0) : send_error(request, "409 Conflict", "OTA is busy"); }
static esp_err_t ota_start_post(httpd_req_t *request) { if (!authorized(request)) return ESP_OK; if (!csrf_authorized(request)) return send_error(request, "403 Forbidden", "Invalid request token"); return door_ota_start() == ESP_OK ? httpd_resp_send(request, "", 0) : send_error(request, "409 Conflict", "No verified update is ready"); }

/* Status polling must work even while TLS leaves little free heap. */
static esp_err_t send_json_string(httpd_req_t *request, const char *value)
{
    /* Largest input is the 127-byte status message; controls expand to 6 bytes. */
    char json[128 * 6 + 3];
    size_t used = 0;
    json[used++] = '"';
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (used + 7 > sizeof(json)) return ESP_ERR_INVALID_SIZE;
        if (*p < 32) {
            snprintf(json + used, 7, "\\u%04x", *p);
            used += 6;
        } else {
            if (*p == '"' || *p == '\\') json[used++] = '\\';
            json[used++] = *p;
        }
    }
    json[used++] = '"';
    return httpd_resp_send_chunk(request, json, used);
}

static esp_err_t rfid_status_get(httpd_req_t *request)
{
    if (!rfid_authorized(request, false)) return ESP_OK;
    door_rfid_status_t status;
    door_rfid_get_status(&status);
    httpd_resp_set_type(request, "application/json");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    char json[96];
    int length = snprintf(json, sizeof(json), "{\"ready\":%s,\"enrolling\":%s,\"message\":",
                          status.ready ? "true" : "false", status.enrolling ? "true" : "false");
    esp_err_t err = httpd_resp_send_chunk(request, json, length);
    if (err == ESP_OK) err = send_json_string(request, status.message);
    if (err == ESP_OK) err = httpd_resp_send_chunk(request, ",\"cards\":[", -1);
    for (unsigned i = 0; err == ESP_OK && i < status.count; ++i) {
        length = snprintf(json, sizeof(json), "%s{\"id\":%u,\"pending\":%s,\"name\":",
                          i ? "," : "", status.cards[i].id, status.cards[i].pending ? "true" : "false");
        err = httpd_resp_send_chunk(request, json, length);
        if (err == ESP_OK) err = send_json_string(request, status.cards[i].name);
        if (err == ESP_OK) err = httpd_resp_send_chunk(request, "}", 1);
    }
    if (err == ESP_OK) err = httpd_resp_send_chunk(request, "]}", 2);
    if (err == ESP_OK) err = httpd_resp_send_chunk(request, NULL, 0);
    return err;
}

static esp_err_t rfid_post(httpd_req_t *request)
{
    if (!rfid_authorized(request, true)) return ESP_OK;
    char content_type[48];
    if (httpd_req_get_hdr_value_str(request, "Content-Type", content_type, sizeof(content_type)) != ESP_OK ||
        strcmp(content_type, "application/json") || request->content_len > 256)
        return send_error(request, "400 Bad Request", "Expected bounded JSON request");
    char *body = receive_form(request);
    if (!body) return send_error(request, "400 Bad Request", "Invalid request body");
    /* Reject embedded NUL/trailing garbage before using the legacy parser. */
    const char *end = NULL;
    cJSON *root = memchr(body, 0, request->content_len) ? NULL : cJSON_ParseWithOpts(body, &end, true);
    esp_err_t err = ESP_ERR_INVALID_ARG;
    if (cJSON_IsObject(root)) {
        if (!strcmp(request->uri, "/api/rfid/enroll")) {
            cJSON *name = cJSON_GetObjectItemCaseSensitive(root, "name");
            if (cJSON_IsString(name) && name->valuestring) err = door_rfid_enroll(name->valuestring);
        } else if (!strcmp(request->uri, "/api/rfid/delete")) {
            cJSON *id = cJSON_GetObjectItemCaseSensitive(root, "id");
            if (cJSON_IsNumber(id) && id->valuedouble >= 1 && id->valuedouble <= DOOR_RFID_MAX_CARDS &&
                id->valuedouble == id->valueint) err = door_rfid_delete(id->valueint);
        } else if (!strcmp(request->uri, "/api/rfid/cancel")) err = door_rfid_cancel();
    }
    cJSON_Delete(root);
    free(body);
    if (err == ESP_OK) return httpd_resp_send(request, "", 0);
    return send_error(request, err == ESP_ERR_INVALID_ARG ? "400 Bad Request" : "409 Conflict",
                      "Card operation failed; check name, reader status, capacity, and storage");
}

static esp_err_t captive_redirect_get(httpd_req_t *request)
{
    if (door_config_is_provisioned()) return send_error(request, "404 Not Found", "Not found");
    httpd_resp_set_status(request, "302 Found");
    httpd_resp_set_hdr(request, "Location", "http://192.168.4.1/");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    return httpd_resp_send(request, "Open the Smart Door setup page", -1);
}

esp_err_t door_web_start(void)
{
    uint8_t random[16];
    esp_fill_random(random, sizeof(random));
    for (unsigned i = 0; i < sizeof(random); ++i) snprintf(s_csrf + i * 2, 3, "%02x", random[i]);
    httpd_config_t config = HTTPD_DEFAULT_CONFIG(); config.stack_size = 6144; config.max_uri_handlers = 16; httpd_handle_t server = NULL;
    esp_err_t err = httpd_start(&server, &config); if (err != ESP_OK) { ESP_LOGE(TAG, "HTTP server start failed: %s", esp_err_to_name(err)); return err; }
    const httpd_uri_t routes[] = {
        { .uri = "/api/rfid/status", .method = HTTP_GET, .handler = rfid_status_get },
        { .uri = "/api/rfid/enroll", .method = HTTP_POST, .handler = rfid_post },
        { .uri = "/api/rfid/delete", .method = HTTP_POST, .handler = rfid_post },
        { .uri = "/api/rfid/cancel", .method = HTTP_POST, .handler = rfid_post },
        { .uri = "/", .method = HTTP_GET, .handler = root_get }, { .uri = "/api/config", .method = HTTP_POST, .handler = config_post },
        { .uri = "/api/ota/status", .method = HTTP_GET, .handler = ota_status_get }, { .uri = "/api/ota/check", .method = HTTP_POST, .handler = ota_check_post },
        { .uri = "/api/ota/start", .method = HTTP_POST, .handler = ota_start_post },
        { .uri = "/generate_204", .method = HTTP_GET, .handler = captive_redirect_get },
        { .uri = "/gen_204", .method = HTTP_GET, .handler = captive_redirect_get },
        { .uri = "/hotspot-detect.html", .method = HTTP_GET, .handler = captive_redirect_get },
        { .uri = "/library/test/success.html", .method = HTTP_GET, .handler = captive_redirect_get },
        { .uri = "/connecttest.txt", .method = HTTP_GET, .handler = captive_redirect_get },
        { .uri = "/ncsi.txt", .method = HTTP_GET, .handler = captive_redirect_get },
        { .uri = "/canonical.html", .method = HTTP_GET, .handler = captive_redirect_get },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); ++i) if ((err = httpd_register_uri_handler(server, &routes[i])) != ESP_OK) return err;
    return ESP_OK;
}
