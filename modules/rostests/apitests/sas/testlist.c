#define STANDALONE
#include <apitest.h>

extern void func_SoftwareSasEvent(void);

const struct test winetest_testlist[] =
{
    { "SoftwareSasEvent", func_SoftwareSasEvent },
    { 0, 0 }
};
