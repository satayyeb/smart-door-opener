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
#define OTA_TASK_STACK_SIZE 8192

static SemaphoreHandle_t s_lock;
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

static int download(const char *url, uint8_t *buffer, size_t capacity)
{
    esp_http_client_config_t config = { .url = url, .cert_pem = (const char *)server_root_ca_start,
                                        .timeout_ms = 15000, .buffer_size = 1024 };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client || esp_http_client_open(client, 0) != ESP_OK) {
        if (client) esp_http_client_cleanup(client);
        return -1;
    }
    int length = esp_http_client_fetch_headers(client);
    if (esp_http_client_get_status_code(client) != 200 || length < 0 || (size_t)length >= capacity) {
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
    int signature_length = download(OTA_SIGNATURE_URL, signature, 512);
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

static void check_task(void *unused)
{
    (void)unused;
    esp_err_t err = door_socket_pause_for_ota();
    if (err == ESP_OK) err = check_now();
    door_socket_resume_after_ota();
    if (err != ESP_OK) set_status(DOOR_OTA_ERROR, 0, "Could not verify the signed update manifest.");
    vTaskDelete(NULL);
}

esp_err_t door_ota_check(void)
{
    door_ota_status_t status; door_ota_get_status(&status);
    if (status.state == DOOR_OTA_CHECKING || status.state == DOOR_OTA_DOWNLOADING || status.state == DOOR_OTA_VERIFYING) return ESP_ERR_INVALID_STATE;
    set_status(DOOR_OTA_CHECKING, 0, "Checking GitHub for signed updates...");
    esp_err_t err = door_socket_pause_for_ota();
    if (err != ESP_OK) { set_status(DOOR_OTA_ERROR, 0, "Could not pause the server connection."); return err; }
    if (xTaskCreate(check_task, "ota_check", OTA_TASK_STACK_SIZE, NULL, 3, NULL) != pdPASS) {
        door_socket_resume_after_ota(); return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static void update_task(void *unused)
{
    (void)unused;
    if (door_socket_pause_for_ota() != ESP_OK) {
        set_status(DOOR_OTA_ERROR, 0, "Could not pause the server connection for a safe update.");
        vTaskDelete(NULL);
        return;
    }
    esp_http_client_config_t config = { .url = s_firmware_url, .cert_pem = (const char *)server_root_ca_start,
                                        .timeout_ms = 15000, .buffer_size = 2048 };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    const esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
    esp_ota_handle_t handle = 0;
    bool begun = false;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha); mbedtls_sha256_starts_ret(&sha, 0);
    if (!client || !partition || esp_http_client_open(client, 0) != ESP_OK) goto failed;
    int length = esp_http_client_fetch_headers(client);
    if (esp_http_client_get_status_code(client) != 200 || length <= 0 || (size_t)length > partition->size ||
        esp_ota_begin(partition, length, &handle) != ESP_OK) goto failed;
    begun = true;
    uint8_t buffer[2048]; int total = 0;
    while (total < length) {
        int count = esp_http_client_read(client, (char *)buffer, sizeof(buffer));
        if (count <= 0 || esp_ota_write(handle, buffer, count) != ESP_OK) goto failed;
        mbedtls_sha256_update_ret(&sha, buffer, count); total += count;
        set_status(DOOR_OTA_DOWNLOADING, (unsigned)((uint64_t)total * 100 / length), "Downloading signed firmware...");
    }
    set_status(DOOR_OTA_VERIFYING, 100, "Verifying firmware signature and image...");
    uint8_t actual[32]; mbedtls_sha256_finish_ret(&sha, actual);
    if (memcmp(actual, s_expected_sha256, sizeof(actual)) || esp_ota_end(handle) != ESP_OK) { begun = false; goto failed; }
    begun = false;
    if (esp_ota_set_boot_partition(partition) != ESP_OK) goto failed;
    esp_http_client_close(client); esp_http_client_cleanup(client); mbedtls_sha256_free(&sha);
    set_status(DOOR_OTA_READY, 100, "Verified. Restarting into the new firmware...");
    vTaskDelay(pdMS_TO_TICKS(1500)); esp_restart();
failed:
    if (begun) esp_ota_end(handle);
    if (client) { esp_http_client_close(client); esp_http_client_cleanup(client); }
    mbedtls_sha256_free(&sha);
    door_socket_resume_after_ota();
    set_status(DOOR_OTA_ERROR, 0, "Firmware download or verification failed; the current image remains active.");
    vTaskDelete(NULL);
}

esp_err_t door_ota_start(void)
{
    door_ota_status_t status; door_ota_get_status(&status);
    if (status.state != DOOR_OTA_AVAILABLE || !s_firmware_url[0]) return ESP_ERR_INVALID_STATE;
    set_status(DOOR_OTA_DOWNLOADING, 0, "Starting firmware download...");
    esp_err_t err = door_socket_pause_for_ota();
    if (err != ESP_OK) { set_status(DOOR_OTA_ERROR, 0, "Could not pause the server connection."); return err; }
    if (xTaskCreate(update_task, "ota_update", OTA_TASK_STACK_SIZE, NULL, 4, NULL) != pdPASS) {
        door_socket_resume_after_ota(); return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static void remote_update_task(void *unused)
{
    (void)unused;
    esp_err_t err = door_socket_pause_for_ota();
    if (err == ESP_OK) err = check_now();
    if (err == ESP_OK && s_status.state == DOOR_OTA_AVAILABLE) update_task(NULL);
    door_socket_resume_after_ota();
    if (err != ESP_OK && s_status.state != DOOR_OTA_UP_TO_DATE)
        set_status(DOOR_OTA_ERROR, 0, "Remote update check or verification failed.");
    vTaskDelete(NULL);
}

esp_err_t door_ota_update_latest(void)
{
    door_ota_status_t status; door_ota_get_status(&status);
    if (status.state == DOOR_OTA_CHECKING || status.state == DOOR_OTA_DOWNLOADING || status.state == DOOR_OTA_VERIFYING) return ESP_ERR_INVALID_STATE;
    set_status(DOOR_OTA_CHECKING, 0, "Backend requested a signed firmware update.");
    door_socket_request_ota_pause();
    if (xTaskCreate(remote_update_task, "ota_remote", OTA_TASK_STACK_SIZE, NULL, 4, NULL) != pdPASS) {
        door_socket_resume_after_ota(); return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
