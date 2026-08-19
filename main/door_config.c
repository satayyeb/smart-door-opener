#include "door_config.h"

#include <string.h>
#include "esp_system.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

#define NVS_NAMESPACE "door"
#define NVS_CONFIG_KEY "config"

static door_config_t s_config;
static bool s_provisioned;

typedef struct {
    uint32_t version;
    bool must_change_password;
    char ssid[DOOR_WIFI_NETWORKS_MAX][DOOR_SSID_MAX + 1];
    char wifi_password[DOOR_WIFI_NETWORKS_MAX][DOOR_WIFI_PASSWORD_MAX + 1];
    char websocket_uri[DOOR_WS_URI_MAX + 1];
    char authorization_token[DOOR_TOKEN_MAX + 1];
    uint8_t password_salt[16];
    uint8_t password_hash[32];
} door_config_v4_t;

static void hash_password(const uint8_t salt[16], const char *password, uint8_t output[32])
{
    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    mbedtls_sha256_starts_ret(&context, 0);
    mbedtls_sha256_update_ret(&context, salt, 16);
    mbedtls_sha256_update_ret(&context, (const unsigned char *)password, strlen(password));
    mbedtls_sha256_finish_ret(&context, output);
    mbedtls_sha256_free(&context);
}

esp_err_t door_config_init(void)
{
    memset(&s_config, 0, sizeof(s_config));
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    size_t size = sizeof(s_config);
    if (err == ESP_OK) {
        err = nvs_get_blob(handle, NVS_CONFIG_KEY, &s_config, &size);
        nvs_close(handle);
    } else if (err != ESP_ERR_NVS_NOT_FOUND) {
        return err;
    }
    bool valid = err == ESP_OK && size == sizeof(s_config) && s_config.version == DOOR_CONFIG_VERSION;
    if (!valid && err == ESP_OK && size == sizeof(door_config_v4_t) && s_config.version == 4) {
        door_config_v4_t old;
        memcpy(&old, &s_config, sizeof(old));
        memset(&s_config, 0, sizeof(s_config));
        s_config.version = DOOR_CONFIG_VERSION;
        memcpy(s_config.ssid, old.ssid, sizeof(old.ssid));
        memcpy(s_config.wifi_password, old.wifi_password, sizeof(old.wifi_password));
        strlcpy(s_config.websocket_uri, old.websocket_uri, sizeof(s_config.websocket_uri));
        strlcpy(s_config.authorization_token, old.authorization_token, sizeof(s_config.authorization_token));
        valid = true;
        nvs_handle_t migration = 0;
        err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &migration);
        if (err == ESP_OK) err = nvs_set_blob(migration, NVS_CONFIG_KEY, &s_config, sizeof(s_config));
        if (err == ESP_OK) err = nvs_commit(migration);
        if (migration) nvs_close(migration);
        if (err != ESP_OK) return err;
    }
    if (!valid) {
        memset(&s_config, 0, sizeof(s_config));
        s_config.version = DOOR_CONFIG_VERSION;
        strlcpy(s_config.websocket_uri, DOOR_DEFAULT_WEBSOCKET_URI,
                sizeof(s_config.websocket_uri));
        nvs_handle_t write_handle = 0;
        err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &write_handle);
        if (err == ESP_OK) err = nvs_set_blob(write_handle, NVS_CONFIG_KEY, &s_config, sizeof(s_config));
        if (err == ESP_OK) err = nvs_commit(write_handle);
        if (write_handle) nvs_close(write_handle);
        if (err != ESP_OK) return err;
    } else if (!s_config.websocket_uri[0]) {
        /* Preserve existing unprovisioned devices while giving them the new default. */
        strlcpy(s_config.websocket_uri, DOOR_DEFAULT_WEBSOCKET_URI,
                sizeof(s_config.websocket_uri));
        nvs_handle_t write_handle = 0;
        err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &write_handle);
        if (err == ESP_OK) err = nvs_set_blob(write_handle, NVS_CONFIG_KEY, &s_config, sizeof(s_config));
        if (err == ESP_OK) err = nvs_commit(write_handle);
        if (write_handle) nvs_close(write_handle);
        if (err != ESP_OK) return err;
    }
    s_provisioned = s_config.ssid[0][0] && s_config.websocket_uri[0];
    return ESP_OK;
}

bool door_config_is_provisioned(void) { return s_provisioned; }
bool door_config_panel_password_set(void) { return s_config.panel_password_set; }

void door_config_get(door_config_t *out)
{
    if (out) memcpy(out, &s_config, sizeof(*out));
}

esp_err_t door_config_save(const char ssid[][DOOR_SSID_MAX + 1],
                           const char wifi_password[][DOOR_WIFI_PASSWORD_MAX + 1],
                           const char *websocket_uri, const char *authorization_token)
{
    if (!ssid || !wifi_password || !ssid[0][0] || !websocket_uri ||
        strlen(websocket_uri) > DOOR_WS_URI_MAX ||
        (strncmp(websocket_uri, "wss://", 6) && strncmp(websocket_uri, "ws://", 5)) ||
        !authorization_token || strlen(authorization_token) > DOOR_TOKEN_MAX ||
        strchr(authorization_token, '\r') || strchr(authorization_token, '\n')) return ESP_ERR_INVALID_ARG;

    door_config_t next = s_config;
    for (int i = 0; i < DOOR_WIFI_NETWORKS_MAX; ++i) {
        if (strlen(ssid[i]) > DOOR_SSID_MAX || strlen(wifi_password[i]) > DOOR_WIFI_PASSWORD_MAX)
            return ESP_ERR_INVALID_ARG;
        strlcpy(next.ssid[i], ssid[i], sizeof(next.ssid[i]));
        strlcpy(next.wifi_password[i], wifi_password[i], sizeof(next.wifi_password[i]));
    }
    strlcpy(next.websocket_uri, websocket_uri, sizeof(next.websocket_uri));
    strlcpy(next.authorization_token, authorization_token, sizeof(next.authorization_token));

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) err = nvs_set_blob(handle, NVS_CONFIG_KEY, &next, sizeof(next));
    if (err == ESP_OK) err = nvs_commit(handle);
    if (handle) nvs_close(handle);
    if (err == ESP_OK) { memcpy(&s_config, &next, sizeof(next)); s_provisioned = true; }
    return err;
}

esp_err_t door_config_set_panel_password(const char *new_password)
{
    if (!new_password || (new_password[0] && strlen(new_password) < DOOR_ADMIN_PASSWORD_MIN))
        return ESP_ERR_INVALID_ARG;
    door_config_t next = s_config;
    memset(next.password_salt, 0, sizeof(next.password_salt));
    memset(next.password_hash, 0, sizeof(next.password_hash));
    next.panel_password_set = new_password[0] != '\0';
    if (next.panel_password_set) {
        esp_fill_random(next.password_salt, sizeof(next.password_salt));
        hash_password(next.password_salt, new_password, next.password_hash);
    }
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) err = nvs_set_blob(handle, NVS_CONFIG_KEY, &next, sizeof(next));
    if (err == ESP_OK) err = nvs_commit(handle);
    if (handle) nvs_close(handle);
    if (err == ESP_OK) memcpy(&s_config, &next, sizeof(next));
    return err;
}

bool door_config_check_password(const char *password)
{
    if (!s_config.panel_password_set) return true;
    if (!password) return false;
    uint8_t candidate[32];
    hash_password(s_config.password_salt, password, candidate);
    unsigned difference = 0;
    for (size_t i = 0; i < sizeof(candidate); ++i) difference |= candidate[i] ^ s_config.password_hash[i];
    return difference == 0;
}

esp_err_t door_config_erase(void)
{
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) err = nvs_erase_key(handle, NVS_CONFIG_KEY);
    if (err == ESP_OK) err = nvs_commit(handle);
    if (handle) nvs_close(handle);
    if (err == ESP_OK) { memset(&s_config, 0, sizeof(s_config)); s_provisioned = false; }
    return err;
}
