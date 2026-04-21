#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct { char level[32]; char msg[128]; int seq; } LogEntry;

void write_log(LogEntry* e) {
    fprintf(stderr, "[%s] %s\n", e->level, e->msg);
}

int log_event(const char* level, const char* msg) {
    LogEntry* e = (LogEntry*)malloc(sizeof(LogEntry));
    strncpy(e->level, level, sizeof(e->level) - 1);
    e->level[sizeof(e->level) - 1] = '\0';
    strncpy(e->msg, msg, sizeof(e->msg) - 1);
    e->msg[sizeof(e->msg) - 1] = '\0';
    e->seq = 0;
    write_log(e);
    free(e);
    return 0;
}

int main() {
    log_event("INFO", "startup complete");
    return 0;
}
