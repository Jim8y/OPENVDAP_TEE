
SET(Boost_USE_MULTITHREADED ON)
FIND_PACKAGE(Boost 1.35 REQUIRED COMPONENTS system thread)

add_custom_command(OUTPUT openvdap_u.h openvdap_u.c openvdap_args.h
        DEPENDS ${CMAKE_SOURCE_DIR}/openvdap/openvdap.edl
        COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/openvdap/openvdap.edl
        --search-path ${OE_INCLUDEDIR} --search-path
        ${OE_INCLUDEDIR}/openenclave/edl/sgx)


file(GLOB OPENVDAP_HOST_SRCS
        ${CMAKE_SOURCE_DIR}/openvdap/host/src/*.cpp
        )

add_executable(openvdap_host
        ${OPENVDAP_HOST_SRCS}
        ${CMAKE_CURRENT_BINARY_DIR}/openvdap_u.c)

target_include_directories(openvdap_host PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}/openvdap/
        ${CMAKE_SOURCE_DIR}/openvdap/common
        ${CMAKE_SOURCE_DIR}/openvdap/host/include
        ${Boost_INCLUDE_DIR}
        )

target_link_libraries(openvdap_host openenclave::oehost ${Boost_LIBRARIES})
