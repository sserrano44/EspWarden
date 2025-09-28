# Main component CMakeLists.txt
set(COMPONENT_SRCS
    "main.c"
    "device_mode.c"
    "wifi_manager.c"
    "https_server.c"
    "captive_dns.c"
    "auth_manager.c"
    "crypto_manager.c"
    "storage_manager.c"
    "policy_engine.c"
    "rate_limiter.c"
    "api_handlers.c"
)

# Add emulator stubs if building for emulator
if(CONFIG_EMULATOR_BUILD)
    list(APPEND COMPONENT_SRCS "emulator_stubs.c")
endif()

idf_component_register(
    SRCS ${COMPONENT_SRCS}
    INCLUDE_DIRS
        "."
        "include"
    EMBED_TXTFILES
        "certs/server_cert.pem"
        "certs/server_key.pem"
    REQUIRES
        nvs_flash
        esp_wifi
        esp_netif
        esp_http_server
        mbedtls
        esp_https_server
        json
        spiffs
        esp_timer
        app_update
        esp_driver_gpio
        trezor-crypto
)