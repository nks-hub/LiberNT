
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl)
add_rpc_files(client ${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl/wlsas.idl)
spec2def(sas.dll sas.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    sas.c
    ${CMAKE_CURRENT_BINARY_DIR}/wlsas_c.c
    ${CMAKE_CURRENT_BINARY_DIR}/sas.def)

add_library(sas MODULE ${SOURCE} sas.rc)
set_module_type(sas win32dll UNICODE ENTRYPOINT 0)
target_link_libraries(sas ${PSEH_LIB})
add_importlibs(sas advapi32 rpcrt4 kernel32 ntdll)
add_cd_file(TARGET sas DESTINATION reactos/system32 FOR all)
