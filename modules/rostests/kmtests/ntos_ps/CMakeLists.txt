
include_directories(../include)

#
# PsNotifyApc
#
list(APPEND PSNOTIFYAPC_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    PsNotifyApc_drv.c)

add_library(psnotifyapc_drv MODULE ${PSNOTIFYAPC_DRV_SOURCE})
set_module_type(psnotifyapc_drv kernelmodedriver)
target_link_libraries(psnotifyapc_drv kmtest_printf ${PSEH_LIB})
add_importlibs(psnotifyapc_drv ntoskrnl hal)
target_compile_definitions(psnotifyapc_drv PRIVATE KMT_STANDALONE_DRIVER)
add_rostests_file(TARGET psnotifyapc_drv)

#
# XpdmVersion
#
list(APPEND XPDMVERSION_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    XpdmVersion_drv.c)

add_library(xpdmversion_drv MODULE ${XPDMVERSION_DRV_SOURCE})
set_module_type(xpdmversion_drv kernelmodedriver)
target_link_libraries(xpdmversion_drv kmtest_printf ${PSEH_LIB})
add_importlibs(xpdmversion_drv videoprt ntoskrnl hal)
target_compile_definitions(xpdmversion_drv PRIVATE KMT_STANDALONE_DRIVER)
if(MSVC)
    target_link_options(xpdmversion_drv PRIVATE /OSVERSION:5.1)
else()
    target_link_options(xpdmversion_drv PRIVATE -Wl,--major-os-version,5 -Wl,--minor-os-version,1)
endif()
add_rostests_file(TARGET xpdmversion_drv)
