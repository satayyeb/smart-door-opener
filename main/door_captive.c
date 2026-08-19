#include "door_captive.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#define DNS_PORT 53
#define DNS_PACKET_MAX 512
#define DNS_TASK_STACK_SIZE 2048

static const char *TAG = "door_captive";

static size_t question_end(const uint8_t *packet, size_t length)
{
    size_t offset = 12;
    while (offset < length && packet[offset]) {
        uint8_t label_length = packet[offset++];
        if (label_length > 63 || offset + label_length > length) return 0;
        offset += label_length;
    }
    if (offset >= length || offset + 5 > length) return 0;
    return offset + 5;
}

static void captive_dns_task(void *unused)
{
    (void)unused;
    int server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server < 0) {
        ESP_LOGE(TAG, "Could not create captive DNS socket");
        vTaskDelete(NULL);
        return;
    }
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(DNS_PORT),
                                   .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) {
        ESP_LOGE(TAG, "Could not bind captive DNS port");
        close(server);
        vTaskDelete(NULL);
        return;
    }
    uint8_t packet[DNS_PACKET_MAX];
    for (;;) {
        struct sockaddr_in client; socklen_t client_length = sizeof(client);
        int length = recvfrom(server, packet, sizeof(packet) - 16, 0,
                              (struct sockaddr *)&client, &client_length);
        if (length < 12 || packet[4] != 0 || packet[5] != 1) continue;
        size_t end = question_end(packet, length);
        if (!end) continue;
        bool is_address_query = packet[end - 4] == 0 && packet[end - 3] == 1 &&
                                packet[end - 2] == 0 && packet[end - 1] == 1;
        packet[2] = 0x81; packet[3] = 0x80;
        packet[6] = 0; packet[7] = is_address_query ? 1 : 0;
        packet[8] = packet[9] = packet[10] = packet[11] = 0;
        size_t response_length = end;
        if (is_address_query) {
            static const uint8_t answer[] = {
                0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x3c, 0x00, 0x04, 192, 168, 4, 1,
            };
            memcpy(packet + response_length, answer, sizeof(answer));
            response_length += sizeof(answer);
        }
        sendto(server, packet, response_length, 0, (struct sockaddr *)&client, client_length);
    }
}

esp_err_t door_captive_start(void)
{
    return xTaskCreate(captive_dns_task, "captive_dns", DNS_TASK_STACK_SIZE, NULL, 3, NULL) == pdPASS
               ? ESP_OK : ESP_ERR_NO_MEM;
}
