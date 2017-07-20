#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
const int N = 10000;


void sort(int *a, int size) {
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size - 1; j++) {
            if (a[j] > a[j + 1]) {
                int temp = a[j];
                a[j] = a[j + 1];
                a[j + 1] = temp;
            }
        }
    }
}

void test(int size) {
    int *a = (int *)malloc(size * sizeof(int));
    srand((unsigned int)time(0));
    for (int i = 0; i < size; i++) {
        a[i] = rand() % (size * 10);
    }
    sort(a, size);
    /*
    for (int i = 0; i < size; i++) {
        printf("%d\t", a[i]);
        if (i % 10 == 9) printf("\n");
    }
    */
}

int main(int argc, char *argv[]) {
    int size = 0;
    if (argc > 1) {
        size = atoi(argv[1]);
    } else {
        size = N;
    }
    test(size);
    return 0;
}
