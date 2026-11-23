
spec2def(winspool_apitest_drv.dll driver.spec)

add_library(winspool_apitest_drv MODULE driver.c driver.rc ${CMAKE_CURRENT_BINARY_DIR}/winspool_apitest_drv.def)
set_module_type(winspool_apitest_drv module UNICODE ENTRYPOINT 0)
add_rostests_file(TARGET winspool_apitest_drv)
