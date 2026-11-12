
add_library(winspool_apitest_drv MODULE driver.rc)
set_module_type(winspool_apitest_drv module UNICODE ENTRYPOINT 0)
add_rostests_file(TARGET winspool_apitest_drv)
