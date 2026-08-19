idf_component_register(SRCS "main.c" "door_captive.c" "door_config.c" "door_control.c" "door_time.c" "door_wifi.c"
                            "door_web.c" "door_socket.c" "door_ota.c"
                       INCLUDE_DIRS "."
                       EMBED_TXTFILES "certs/server_root_ca.pem" "certs/ota_public_key.pem"
                       REQUIRES app_update esp8266 esp_event esp_http_client esp_http_server esp-tls http_parser json lwip
                                mbedtls nvs_flash pthread tcp_transport tcpip_adapter)

target_compile_definitions(${COMPONENT_LIB} PRIVATE FIRMWARE_VERSION="${PROJECT_VER}")
