
spec2def(nsisvc.dll nsisvc.spec)

add_library(nsisvc MODULE
    nsisvc.c
    nsisvc.rc
    ${CMAKE_CURRENT_BINARY_DIR}/nsisvc.def)

set_module_type(nsisvc win32dll UNICODE)
add_importlibs(nsisvc advapi32 msvcrt kernel32 ntdll)
add_cd_file(TARGET nsisvc DESTINATION reactos/system32 FOR all)
