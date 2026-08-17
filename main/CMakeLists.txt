idf_component_register(SRCS "main.c" "door_config.c" "door_control.c" "door_wifi.c"
                            "door_web.c" "door_socket.c"
                       INCLUDE_DIRS "."
                       EMBED_TXTFILES "certs/server_root_ca.pem"
                       REQUIRES esp8266 esp_event esp_http_server esp-tls http_parser json lwip
                                mbedtls nvs_flash pthread tcp_transport tcpip_adapter)
