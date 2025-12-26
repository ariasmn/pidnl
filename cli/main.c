#include "strait.h"
#include <stdio.h>
#include <time.h>

int main(void) {
    print_hello();

    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    printf("Current date: %s", asctime(tm));

    return 0;
}
