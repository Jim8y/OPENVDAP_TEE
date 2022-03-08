add_custom_command(OUTPUT openvdap_t.h openvdap_t.c openvdap_args.h
        DEPENDS ${CMAKE_SOURCE_DIR}/openvdap/openvdap.edl
        COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/openvdap/openvdap.edl
        --search-path ${OE_INCLUDEDIR} --search-path
        ${OE_INCLUDEDIR}/openenclave/edl/sgx)


file(GLOB OPENVDAP_ENCLAVE_SRCS
        ${CMAKE_SOURCE_DIR}/openvdap/enclave/src/*.cpp
        )

add_executable(openvdap_enclave
        ${OPENVDAP_ENCLAVE_SRCS}
        ${CMAKE_SOURCE_DIR}/openvdap/enclave/sqlite3.c
        ${CMAKE_SOURCE_DIR}/openvdap/enclave/src/ocall_interface.c
        ${CMAKE_CURRENT_BINARY_DIR}/openvdap_t.c)


target_compile_definitions(openvdap_enclave PUBLIC OE_API_VERSION=2)

target_include_directories(openvdap_enclave PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}/openvdap/
        ${CMAKE_SOURCE_DIR}/openvdap/common
        ${CMAKE_SOURCE_DIR}/openvdap/enclave/include/
        )

target_link_libraries(openvdap_enclave
        openenclave::oeenclave openenclave::oelibc openenclave::oelibcxx openenclave::oecrypto${OE_CRYPTO_LIB})