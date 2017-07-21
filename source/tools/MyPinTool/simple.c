#include <string.h>
#include <stdlib.h>

void vul() {
    int a[0];
    memset(a, 0xff, 4 * sizeof(int));
}

int main() {
    vul();
}
