
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl)
add_rpc_file(client ${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl/wlsas.idl PREFIX_SERVER Test_)
add_rpc_file(server ${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl/wlsas.idl PREFIX_SERVER Test_)

list(APPEND SOURCE
    SoftwareSasEvent.c
    testlist.c
    ${CMAKE_CURRENT_BINARY_DIR}/wlsas_c.c
    ${CMAKE_CURRENT_BINARY_DIR}/wlsas_s.c)

add_executable(sas_apitest ${SOURCE})
target_link_libraries(sas_apitest wine ${PSEH_LIB})
set_module_type(sas_apitest win32cui)
add_importlibs(sas_apitest sas advapi32 rpcrt4 msvcrt kernel32 ntdll)
add_rostests_file(TARGET sas_apitest)
