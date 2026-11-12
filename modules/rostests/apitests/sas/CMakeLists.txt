
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl)
add_rpc_files(client ${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl/wlsas.idl)

list(APPEND SOURCE
    SoftwareSasEvent.c
    testlist.c
    ${CMAKE_CURRENT_BINARY_DIR}/wlsas_c.c)

add_executable(sas_apitest ${SOURCE})
target_link_libraries(sas_apitest wine ${PSEH_LIB})
set_module_type(sas_apitest win32cui)
add_importlibs(sas_apitest advapi32 rpcrt4 msvcrt kernel32 ntdll)
add_rostests_file(TARGET sas_apitest)
