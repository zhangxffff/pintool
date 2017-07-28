#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void vul() {
    int i;
    int a[0];
    printf("%x\n", a);
    read(0, a, 40);
    i = 0;
    while (a[i] != 0) i++;
}

int main() {
    vul();
}
