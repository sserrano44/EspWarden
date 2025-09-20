# ESP32 Remote Signer - CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

# Set the target and project name
set(CMAKE_TOOLCHAIN_FILE $ENV{IDF_PATH}/tools/cmake/toolchain-esp32.cmake)

project(esp32-remote-signer)

# Include ESP-IDF build system
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Define the project
project(esp32-remote-signer)