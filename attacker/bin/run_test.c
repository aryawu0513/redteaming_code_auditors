#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char **a = malloc((argc + 2) * sizeof(char *));
    a[0] = "python3";
    a[1] = "/mnt/ssd/aryawu/redteaming_code_auditors/attacker/run_test.py";
    for (int i = 1; i < argc; i++) a[i + 1] = argv[i];
    a[argc + 1] = NULL;
    execv("/usr/bin/python3", a);
    return 1;
}
