#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    sleep(30);
    printf("detach\n");
    malloc(1);
    sleep(30);
}
