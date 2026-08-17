#include "door_socket.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"
#include "door_config.h"
#include "door_control.h"
#include "door_wifi.h"
#include "esp_log.h"
#include "esp_transport.h"
#include "esp_transport_ssl.h"
#include "esp_transport_tcp.h"
#include "esp_transport_ws.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "http_parser.h"
#include "lwip/apps/sntp.h"

#define FIRMWARE_VERSION "3.0.0-esp8266"
#define WS_MESSAGE_MAX 1024
#define WS_CONNECT_TIMEOUT_MS 10000
#define WS_IO_TIMEOUT_MS 3000
#define WS_RECONNECT_MS 5000
#define WS_TASK_STACK_SIZE 8192

static const char *TAG = "door_socket";
static esp_transport_handle_t s_socket;

extern const unsigned char server_root_ca_start[] asm("_binary_server_root_ca_pem_start");
extern const unsigned char server_root_ca_end[] asm("_binary_server_root_ca_pem_end");

typedef struct {
    bool secure;
    char host[128];
    char path[DOOR_WS_URI_MAX + 1];
    int port;
} websocket_url_t;

static bool parse_url(const char *uri, websocket_url_t *parsed)
{
    struct http_parser_url result;
    memset(&result, 0, sizeof(result));
    if (http_parser_parse_url(uri, strlen(uri), 0, &result) != 0 ||
        !(result.field_set & (1 << UF_SCHEMA)) || !(result.field_set & (1 << UF_HOST)) ||
        (result.field_set & (1 << UF_USERINFO)) || (result.field_set & (1 << UF_FRAGMENT))) return false;
    const char *scheme = uri + result.field_data[UF_SCHEMA].off;
    size_t scheme_length = result.field_data[UF_SCHEMA].len;
    parsed->secure = scheme_length == 3 && !strncmp(scheme, "wss", 3);
    if (!parsed->secure && !(scheme_length == 2 && !strncmp(scheme, "ws", 2))) return false;
    size_t host_length = result.field_data[UF_HOST].len;
    if (!host_length || host_length >= sizeof(parsed->host)) return false;
    memcpy(parsed->host, uri + result.field_data[UF_HOST].off, host_length);
    parsed->host[host_length] = '\0';
    parsed->port = result.field_set & (1 << UF_PORT) ? result.port : (parsed->secure ? 443 : 80);
    if (result.field_set & (1 << UF_PATH)) {
        size_t start = result.field_data[UF_PATH].off;
        size_t length = strlen(uri) - start;
        if (length >= sizeof(parsed->path)) return false;
        memcpy(parsed->path, uri + start, length + 1);
    } else strlcpy(parsed->path, "/", sizeof(parsed->path));
    return true;
}

static bool synchronize_clock(void)
{
    static bool started;
    if (!started) {
        sntp_setoperatingmode(SNTP_OPMODE_POLL);
        sntp_setservername(0, "pool.ntp.org");
        sntp_init();
        started = true;
    }
    time_t now = 0;
    for (int attempt = 0; attempt < 30; ++attempt) {
        time(&now);
        if (now > 1704067200) return true; /* 2024-01-01 */
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    ESP_LOGW(TAG, "Clock is not synchronized; postponing TLS connection");
    return false;
}

static bool send_frame(ws_transport_opcodes_t opcode, char *payload, size_t length)
{
    return s_socket && esp_transport_ws_send_raw(s_socket, opcode, payload, length, WS_IO_TIMEOUT_MS) == (int)length;
}

static void send_response(bool success, const char *message)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return;
    cJSON_AddBoolToObject(root, "success", success);
    cJSON_AddStringToObject(root, "message", message);
    char *json = cJSON_PrintUnformatted(root);
    if (json) {
        send_frame(WS_TRANSPORT_OPCODES_TEXT, json, strlen(json));
        free(json);
    }
    cJSON_Delete(root);
}

static void handle_text(char *text)
{
    cJSON *root = cJSON_Parse(text);
    cJSON *command = root ? cJSON_GetObjectItemCaseSensitive(root, "command") : NULL;
    if (!cJSON_IsString(command)) send_response(false, "You must specify the 'command' string.");
    else if (!strcmp(command->valuestring, "get-version")) send_response(true, FIRMWARE_VERSION);
    else if (!strcmp(command->valuestring, "open-door")) {
        esp_err_t err = door_control_open();
        send_response(err == ESP_OK, err == ESP_OK ? "Door opened successfully." : "Door relay is already active.");
    } else send_response(false, "Unknown command.");
    cJSON_Delete(root);
}

static bool receive_frame(void)
{
    char payload[WS_MESSAGE_MAX + 1];
    int first = esp_transport_read(s_socket, payload, WS_MESSAGE_MAX, 1000);
    if (first == 0) return true;
    if (first < 0) return false;
    int expected = esp_transport_ws_get_read_payload_len(s_socket);
    ws_transport_opcodes_t opcode = esp_transport_ws_get_read_opcode(s_socket);
    if (expected > WS_MESSAGE_MAX) {
        ESP_LOGW(TAG, "Closing connection after oversized WebSocket frame (%d bytes)", expected);
        return false;
    }
    int total = first;
    while (total < expected) {
        int count = esp_transport_read(s_socket, payload + total, expected - total, WS_IO_TIMEOUT_MS);
        if (count <= 0) return false;
        total += count;
    }
    payload[total] = '\0';
    if (opcode == WS_TRANSPORT_OPCODES_TEXT) handle_text(payload);
    else if (opcode == WS_TRANSPORT_OPCODES_PING) send_frame(WS_TRANSPORT_OPCODES_PONG, payload, total);
    else if (opcode == WS_TRANSPORT_OPCODES_CLOSE) return false;
    return true;
}

static void socket_session(const door_config_t *config)
{
    door_wifi_set_websocket_connected(false);
    bool connected = false;
    websocket_url_t url = {0};
    if (!parse_url(config->websocket_uri, &url)) { ESP_LOGE(TAG, "Invalid WebSocket URI"); return; }
    if (url.secure && !synchronize_clock()) return;

    /* Standalone SSL transports in ESP8266 RTOS SDK v3.4 have no error_handle,
     * but the DNS failure path unconditionally copies into it. A transport list
     * owns and assigns the required error buffer, preventing StoreProhibited on
     * an unresolved hostname. */
    esp_transport_list_handle_t transports = esp_transport_list_init();
    if (!transports) return;
    esp_transport_handle_t parent = url.secure ? esp_transport_ssl_init() : esp_transport_tcp_init();
    if (!parent) { esp_transport_list_destroy(transports); return; }
    esp_err_t add_err = esp_transport_list_add(transports, parent, url.secure ? "wss-parent" : "ws-parent");
    if (add_err != ESP_OK) {
        esp_transport_destroy(parent);
        esp_transport_list_destroy(transports);
        return;
    }
    if (url.secure) {
        esp_transport_ssl_set_cert_data(parent, (const char *)server_root_ca_start,
                                        strlen((const char *)server_root_ca_start));
    }
    s_socket = esp_transport_ws_init(parent);
    if (!s_socket) { esp_transport_list_destroy(transports); return; }
    esp_transport_ws_set_path(s_socket, url.path);
    esp_transport_ws_set_user_agent(s_socket, "smart-door-opener/3.0.0-esp8266");
    char *headers = NULL;
    if (config->authorization_token[0]) {
        size_t length = strlen(config->authorization_token) + 32;
        headers = malloc(length);
        if (headers) {
            snprintf(headers, length, "Authorization: %s\r\n", config->authorization_token);
            esp_transport_ws_set_headers(s_socket, headers);
            free(headers);
        }
    }
    if (esp_transport_connect(s_socket, url.host, url.port, WS_CONNECT_TIMEOUT_MS) >= 0) {
        connected = true;
        ESP_LOGI(TAG, "Connected to %s://%s:%d%s", url.secure ? "wss" : "ws", url.host, url.port, url.path);
        door_wifi_set_websocket_connected(true);
        TickType_t last_ping = xTaskGetTickCount();
        while (door_wifi_station_connected()) {
            if (!receive_frame()) break;
            TickType_t now = xTaskGetTickCount();
            if (now - last_ping >= pdMS_TO_TICKS(17000)) {
                char empty = '\0';
                if (!send_frame(WS_TRANSPORT_OPCODES_PING, &empty, 0)) break;
                last_ping = now;
            }
        }
    } else ESP_LOGW(TAG, "Connection failed; retrying in %d ms", WS_RECONNECT_MS);
    door_wifi_set_websocket_connected(false);

    /* A failed TLS connect already closes its connection state. */
    if (connected) esp_transport_close(s_socket);
    esp_transport_destroy(s_socket);
    esp_transport_list_destroy(transports);
    s_socket = NULL;
}

static void websocket_task(void *unused)
{
    (void)unused;
    door_wifi_set_websocket_connected(false);
    for (;;) {
        if (door_config_is_provisioned() && door_wifi_station_connected()) {
            door_config_t config;
            door_config_get(&config);
            socket_session(&config);
        }
        vTaskDelay(pdMS_TO_TICKS(WS_RECONNECT_MS));
    }
}

esp_err_t door_socket_start(void)
{
    BaseType_t result = xTaskCreate(websocket_task, "door_ws", WS_TASK_STACK_SIZE, NULL, 5, NULL);
    return result == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}
