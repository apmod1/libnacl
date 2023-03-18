#include <sodium.h>
#include <string.h>
int main(void)
{
    if (sodium_init() < 0)
    {
        fprintf(stderr, "panic! the library couldn't be initialized; it is not safe to use");
        return 1;
    }

    else if (strcmp(SODIUM_VERSION_STRING, "1.0.18") != 0)
    {
        fprintf(stderr, "version not 1.0.18");
        return 2;
    }

    else
    {
        printf("%s", "Congratulations version is 1.0.18");
        return 0;
    }
}
