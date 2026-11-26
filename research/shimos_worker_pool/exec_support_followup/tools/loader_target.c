#include <stdio.h>
extern int exec_missing_fixture(void);
int main(void) { printf("UNEXPECTED_LOADER_SUCCESS=%d\n", exec_missing_fixture()); return 81; }
