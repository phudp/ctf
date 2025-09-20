#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("[*] PATH: %s\n", getenv("PATH") ? getenv("PATH") : "NULL");

    printf("[*] Trying system(\"sh\")...\n");
    int ret = system("/bin/sh");

    printf("[*] system(\"sh\") returned: %d\n", ret);
    return 0;
}
