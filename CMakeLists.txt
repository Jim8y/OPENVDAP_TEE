cmake_minimum_required(VERSION 3.15)
project(OpenVDAP)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_BUILD_TYPE Release)

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(OE_CRYPTO_LIB
        mbedtls
        CACHE STRING "Crypto library used by enclaves.")

if (LVI_MITIGATION MATCHES ControlFlow)
    # Configure the cmake to use customized compilation toolchain.
    # This package has to be added before `project()`.
    find_package(OpenEnclave-LVI-Mitigation CONFIG REQUIRED)
endif ()

find_package(OpenEnclave CONFIG REQUIRED)

add_subdirectory(enclave)
add_subdirectory(host)

# Generate key
add_custom_command(OUTPUT private.pem public.pem
        COMMAND openssl genrsa -out private.pem -3 3072
        COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(OUTPUT openvdap_enclave.signed
        DEPENDS openvdap_enclave ${CMAKE_SOURCE_DIR}/openvdap.conf private.pem
        COMMAND openenclave::oesign sign -e $<TARGET_FILE:openvdap_enclave> -c
                ${CMAKE_SOURCE_DIR}/openvdap.conf -k private.pem)

add_custom_target(sign ALL DEPENDS openvdap_enclave.signed)


add_custom_target(openvdap
        DEPENDS openvdap_host openvdap_enclave sign
        COMMAND openvdap_host ${CMAKE_BINARY_DIR}/enclave/openvdap_enclave.signed --simulate)