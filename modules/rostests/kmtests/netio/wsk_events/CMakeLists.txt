
include_directories(../../include)

list(APPEND WSKEVENTS_DRV_SOURCE
    ../../kmtest_drv/kmtest_standalone.c
    wsk_events.c)

add_library(wskevents_drv MODULE ${WSKEVENTS_DRV_SOURCE})
set_module_type(wskevents_drv kernelmodedriver)
target_link_libraries(wskevents_drv kmtest_printf uuid ${PSEH_LIB})
add_importlibs(wskevents_drv netio ntoskrnl hal)
target_compile_definitions(wskevents_drv PRIVATE KMT_STANDALONE_DRIVER)
add_rostests_file(TARGET wskevents_drv)
