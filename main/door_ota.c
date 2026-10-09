#include "door_ota.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"
#include "door_socket.h"
#include "door_time.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_image_format.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

#define OTA_MANIFEST_URL "https://github.com/satayyeb/smart-door-opener/releases/latest/download/manifest.json"
#define OTA_SIGNATURE_URL "https://github.com/satayyeb/smart-door-opener/releases/latest/download/manifest.json.sig"
#define OTA_RELEASE_PREFIX "https://github.com/satayyeb/smart-door-opener/releases/"
#define OTA_METADATA_MAX 2048
#define OTA_RANGE_SIZE 4096

static SemaphoreHandle_t s_lock;
static volatile bool s_remote_update_pending;
static volatile bool s_check_pending;
static volatile bool s_install_pending;
static door_ota_status_t s_status = { .state = DOOR_OTA_IDLE, .current_version = FIRMWARE_VERSION };
static char s_firmware_url[512];
static uint8_t s_expected_sha256[32];

extern const unsigned char server_root_ca_start[] asm("_binary_server_root_ca_pem_start");
extern const unsigned char ota_public_key_start[] asm("_binary_ota_public_key_pem_start");
extern const unsigned char ota_public_key_end[] asm("_binary_ota_public_key_pem_end");

static void set_status(door_ota_state_t state, unsigned progress, const char *message)
{
    if (!s_lock) s_lock = xSemaphoreCreateMutex();
    if (s_lock) xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.state = state;
    s_status.progress = progress;
    if (message) strlcpy(s_status.message, message, sizeof(s_status.message));
    if (s_lock) xSemaphoreGive(s_lock);
}

void door_ota_get_status(door_ota_status_t *status)
{
    if (!status) return;
    if (!s_lock) s_lock = xSemaphoreCreateMutex();
    if (s_lock) xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(status, &s_status, sizeof(*status));
    if (s_lock) xSemaphoreGive(s_lock);
}

const char *door_ota_state_name(door_ota_state_t state)
{
    static const char *names[] = { "idle", "checking", "available", "downloading", "verifying", "ready", "up-to-date", "error" };
    return state <= DOOR_OTA_ERROR ? names[state] : "error";
}

/* Streaming HTTP calls do not follow redirects automatically in SDK v3.4. */
static int open_download(esp_http_client_handle_t client)
{
    if (esp_http_client_set_header(client, "Cache-Control", "no-cache") != ESP_OK) return -1;
    for (int redirects = 0; redirects <= 5; ++redirects) {
        char url[sizeof(s_firmware_url) + 48];
        if (esp_http_client_get_url(client, url, sizeof(url)) != ESP_OK) return -1;
        /* Bust cached GitHub redirects, never modify the signed asset URL. */
        if (!strncmp(url, OTA_RELEASE_PREFIX, sizeof(OTA_RELEASE_PREFIX) - 1)) {
            size_t length = strlen(url);
            int added = snprintf(url + length, sizeof(url) - length, "?ota=%lu", (unsigned long)esp_random());
            if (added < 0 || (size_t)added >= sizeof(url) - length ||
                esp_http_client_set_url(client, url) != ESP_OK) return -1;
        }
        ESP_LOGI("door_ota", "HTTPS hop %d: free heap %u", redirects, (unsigned)esp_get_free_heap_size());
        if (esp_http_client_open(client, 0) != ESP_OK) return -1;
        int length = esp_http_client_fetch_headers(client);
        if (length < 0) return -1;
        int status = esp_http_client_get_status_code(client);
        if (status == 200 || status == 206) return length;
        if (redirects == 5 || (status != 301 && status != 302 && status != 303 &&
                              status != 307 && status != 308)) {
            ESP_LOGW("door_ota", "Download rejected HTTP status %d", status);
            return -1;
        }
        /* SDK SSL close returns -1 even after successful cleanup. */
        (void)esp_http_client_close(client);
        if (esp_http_client_set_redirection(client) != ESP_OK ||
            esp_http_client_get_transport_type(client) != HTTP_TRANSPORT_OVER_SSL) return -1;
    }
    return -1;
}

static int download(const char *url, uint8_t *buffer, size_t capacity)
{
    esp_http_client_config_t config = { .url = url, .cert_pem = (const char *)server_root_ca_start,
                                        .timeout_ms = 15000, .buffer_size = 512, .buffer_size_tx = 2048 };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) return -1;
    int length = open_download(client);
    if (length < 0 || esp_http_client_get_status_code(client) != 200) {
        esp_http_client_cleanup(client);
        return -1;
    }
    if ((size_t)length >= capacity) {
        esp_http_client_close(client); esp_http_client_cleanup(client); return -1;
    }
    int total = 0;
    while (total < length) {
        int count = esp_http_client_read(client, (char *)buffer + total, length - total);
        if (count <= 0) break;
        total += count;
    }
    esp_http_client_close(client); esp_http_client_cleanup(client);
    if (total != length) return -1;
    buffer[total] = 0;
    return total;
}

static bool hex_sha256(const char *text, uint8_t output[32])
{
    if (!text || strlen(text) != 64) return false;
    for (int i = 0; i < 32; ++i) {
        unsigned value;
        if (sscanf(text + i * 2, "%2x", &value) != 1) return false;
        output[i] = value;
    }
    return true;
}

static bool verify_manifest(const uint8_t *manifest, size_t manifest_length,
                            const uint8_t *signature, size_t signature_length)
{
    uint8_t hash[32];
    mbedtls_sha256_ret(manifest, manifest_length, hash, 0);
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int result = mbedtls_pk_parse_public_key(&key, ota_public_key_start,
                                              ota_public_key_end - ota_public_key_start);
    if (result == 0) result = mbedtls_pk_verify(&key, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                                                signature, signature_length);
    mbedtls_pk_free(&key);
    return result == 0;
}

static bool version_is_newer(const char *candidate)
{
    unsigned a[3] = {0}, b[3] = {0};
    if (sscanf(candidate, "%u.%u.%u", &a[0], &a[1], &a[2]) != 3 ||
        sscanf(FIRMWARE_VERSION, "%u.%u.%u", &b[0], &b[1], &b[2]) != 3) return strcmp(candidate, FIRMWARE_VERSION) != 0;
    for (int i = 0; i < 3; ++i) { if (a[i] != b[i]) return a[i] > b[i]; }
    return false;
}

static esp_err_t check_now(void)
{
    if (!door_time_ready()) return ESP_ERR_TIMEOUT;
    uint8_t *manifest = malloc(OTA_METADATA_MAX);
    uint8_t *signature = malloc(512);
    if (!manifest || !signature) { free(manifest); free(signature); return ESP_ERR_NO_MEM; }
    int manifest_length = download(OTA_MANIFEST_URL, manifest, OTA_METADATA_MAX);
    int signature_length = manifest_length > 0 ? download(OTA_SIGNATURE_URL, signature, 512) : -1;
    if (manifest_length <= 0 || signature_length <= 0 ||
        !verify_manifest(manifest, manifest_length, signature, signature_length)) {
        free(manifest); free(signature); return ESP_ERR_INVALID_CRC;
    }
    cJSON *root = cJSON_Parse((char *)manifest);
    cJSON *version = root ? cJSON_GetObjectItemCaseSensitive(root, "version") : NULL;
    cJSON *url = root ? cJSON_GetObjectItemCaseSensitive(root, "firmware_url") : NULL;
    cJSON *sha = root ? cJSON_GetObjectItemCaseSensitive(root, "sha256") : NULL;
    bool valid = cJSON_IsString(version) && strlen(version->valuestring) < sizeof(s_status.available_version) &&
                 cJSON_IsString(url) && !strncmp(url->valuestring, OTA_RELEASE_PREFIX, sizeof(OTA_RELEASE_PREFIX) - 1) &&
                 strlen(url->valuestring) < sizeof(s_firmware_url) && cJSON_IsString(sha) && hex_sha256(sha->valuestring, s_expected_sha256);
    if (valid) {
        strlcpy(s_status.available_version, version->valuestring, sizeof(s_status.available_version));
        strlcpy(s_firmware_url, url->valuestring, sizeof(s_firmware_url));
    }
    cJSON_Delete(root); free(manifest); free(signature);
    if (!valid) return ESP_ERR_INVALID_RESPONSE;
    if (!version_is_newer(s_status.available_version)) {
        set_status(DOOR_OTA_UP_TO_DATE, 100, "The installed firmware is current.");
        return ESP_OK;
    }
    set_status(DOOR_OTA_AVAILABLE, 0, "A signed firmware update is available.");
    return ESP_OK;
}

esp_err_t door_ota_check(void)
{
    door_ota_status_t status; door_ota_get_status(&status);
    if (status.state == DOOR_OTA_CHECKING || status.state == DOOR_OTA_DOWNLOADING || status.state == DOOR_OTA_VERIFYING) return ESP_ERR_INVALID_STATE;
    set_status(DOOR_OTA_CHECKING, 0, "Checking GitHub for signed updates...");
    door_socket_request_ota_pause();
    s_check_pending = true;
    return ESP_OK;
}

/* ESP8266 cache selects a 1 MiB window; it cannot relocate within that window. */
static bool image_mapping_valid(const esp_partition_t *partition)
{
    esp_image_metadata_t image;
    const esp_partition_pos_t position = { .offset = partition->address, .size = partition->size };
    if (esp_image_load(ESP_IMAGE_VERIFY, &position, &image) != ESP_OK) return false;
    /* First flash segment fixes the link origin; later SDK segments have padding. */
    uint32_t address = image.segments[0].load_addr;
    if (address != 0x40200000 + (image.segment_data[0] & 0xfffff)) {
        ESP_LOGE("door_ota", "Image cache mapping incompatible with slot at 0x%x", partition->address);
        return false;
    }
    return true;
}

typedef struct {
    unsigned start, end, total;
    bool valid;
} download_range_t;

static esp_err_t range_header(esp_http_client_event_t *event)
{
    if (event->event_id == HTTP_EVENT_ON_HEADER && !strcasecmp(event->header_key, "Content-Range")) {
        download_range_t *range = event->user_data;
        char extra;
        range->valid = sscanf(event->header_value, "bytes %u-%u/%u%c",
                              &range->start, &range->end, &range->total, &extra) == 3 &&
                       range->start <= range->end && range->end < range->total;
    }
    return ESP_OK;
}

static int open_range(esp_http_client_handle_t client, download_range_t *range,
                      unsigned offset, unsigned expected_total, unsigned capacity)
{
    unsigned end = offset + OTA_RANGE_SIZE - 1;
    char header[48];
    snprintf(header, sizeof(header), "bytes=%u-%u", offset, end);
    range->valid = false;
    if (esp_http_client_set_header(client, "Range", header) != ESP_OK) return -1;
    int length = open_download(client);
    if (esp_http_client_get_status_code(client) != 206 || !range->valid ||
        range->start != offset || range->total > capacity ||
        (expected_total && range->total != expected_total)) return -1;
    unsigned expected_end = range->total - 1 < end ? range->total - 1 : end;
    if (range->end != expected_end || length != (int)(range->end - range->start + 1)) return -1;
    return length;
}

static void update_now(void)
{
    if (door_socket_pause_for_ota() != ESP_OK) {
        set_status(DOOR_OTA_ERROR, 0, "Could not pause the server connection for a safe update.");
        return;
    }
    download_range_t range = {0};
    esp_http_client_config_t config = { .url = s_firmware_url, .cert_pem = (const char *)server_root_ca_start,
                                        .timeout_ms = 15000, .buffer_size = 512, .buffer_size_tx = 2048,
                                        .event_handler = range_header, .user_data = &range };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    const esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
    esp_ota_handle_t handle = 0;
    bool begun = false;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    if (mbedtls_sha256_starts_ret(&sha, 0) != 0) goto failed;
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!client || !partition || !running || partition->address == running->address) goto failed;
    int part_length = open_range(client, &range, 0, 0, partition->size);
    if (part_length <= 0) goto failed;
    int length = range.total;
    if (esp_ota_begin(partition, length, &handle) != ESP_OK) goto failed;
    begun = true;
    uint8_t buffer[2048]; int total = 0;
    while (total < length) {
        if (part_length == 0) {
            part_length = open_range(client, &range, total, length, partition->size);
            if (part_length <= 0) goto failed;
        }
        int count = esp_http_client_read(client, (char *)buffer, part_length < sizeof(buffer) ? part_length : sizeof(buffer));
        if (count <= 0 || count > part_length || esp_ota_write(handle, buffer, count) != ESP_OK) goto failed;
        part_length -= count;
        if (mbedtls_sha256_update_ret(&sha, buffer, count) != 0) goto failed;
        total += count;
        set_status(DOOR_OTA_DOWNLOADING, (unsigned)((uint64_t)total * 100 / length), "Downloading signed firmware...");
    }
    set_status(DOOR_OTA_VERIFYING, 100, "Verifying firmware signature and image...");
    uint8_t actual[32];
    if (total != length || mbedtls_sha256_finish_ret(&sha, actual) != 0 ||
        memcmp(actual, s_expected_sha256, sizeof(actual))) goto failed;
    esp_http_client_cleanup(client);
    client = NULL;
    esp_err_t end_result = esp_ota_end(handle);
    begun = false;
    if (end_result != ESP_OK || !image_mapping_valid(partition)) goto failed;
    if (esp_ota_set_boot_partition(partition) != ESP_OK) goto failed;
    mbedtls_sha256_free(&sha);
    set_status(DOOR_OTA_READY, 100, "Verified. Restarting into the new firmware...");
    vTaskDelay(pdMS_TO_TICKS(1500)); esp_restart();
failed:
    /* SDK v3.4 has no esp_ota_abort; end frees the handle without selecting it. */
    if (begun) (void)esp_ota_end(handle);
    if (client) { esp_http_client_close(client); esp_http_client_cleanup(client); }
    mbedtls_sha256_free(&sha);
    door_socket_resume_after_ota();
    set_status(DOOR_OTA_ERROR, 0, "Firmware download or verification failed; the current image remains active.");
}

esp_err_t door_ota_start(void)
{
    door_ota_status_t status; door_ota_get_status(&status);
    if (status.state != DOOR_OTA_AVAILABLE || !s_firmware_url[0]) return ESP_ERR_INVALID_STATE;
    set_status(DOOR_OTA_DOWNLOADING, 0, "Starting firmware download...");
    door_socket_request_ota_pause();
    s_install_pending = true;
    return ESP_OK;
}

void door_ota_run_pending_remote_update(void)
{
    if (s_install_pending) {
        s_install_pending = false;
        update_now();
        door_socket_resume_after_ota();
        return;
    }
    if (!s_remote_update_pending && !s_check_pending) return;
    bool install = s_remote_update_pending;
    s_check_pending = false;
    s_remote_update_pending = false;
    esp_err_t err = door_socket_pause_for_ota();
    if (err == ESP_OK) err = check_now();
    if (install && err == ESP_OK && s_status.state == DOOR_OTA_AVAILABLE) update_now();
    door_socket_resume_after_ota();
    if (err != ESP_OK && s_status.state != DOOR_OTA_UP_TO_DATE)
        set_status(DOOR_OTA_ERROR, 0, "Remote update check or verification failed.");
}

esp_err_t door_ota_update_latest(void)
{
    door_ota_status_t status; door_ota_get_status(&status);
    if (status.state == DOOR_OTA_CHECKING || status.state == DOOR_OTA_DOWNLOADING || status.state == DOOR_OTA_VERIFYING) return ESP_ERR_INVALID_STATE;
    set_status(DOOR_OTA_CHECKING, 0, "Backend requested a signed firmware update.");
    door_socket_request_ota_pause();
    /* Reuse the WebSocket task only after it releases its TLS connection. */
    s_remote_update_pending = true;
    return ESP_OK;
}
