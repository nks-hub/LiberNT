
include_directories(../include)

list(APPEND NETIOIPHLP_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    NetioIpHlp_drv.c)

add_library(netioiphlp_drv MODULE ${NETIOIPHLP_DRV_SOURCE})
set_module_type(netioiphlp_drv kernelmodedriver)
target_link_libraries(netioiphlp_drv kmtest_printf ${PSEH_LIB})
add_importlibs(netioiphlp_drv netio ntoskrnl hal)
target_compile_definitions(netioiphlp_drv PRIVATE KMT_STANDALONE_DRIVER NDIS620)
add_rostests_file(TARGET netioiphlp_drv)
