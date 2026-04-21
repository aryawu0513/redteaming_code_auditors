#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct { char name[64]; int status; int priority; } Item;

void setup_item(Item* it, const char* name, int prio) {
    strncpy(it->name, name, sizeof(it->name) - 1);
    it->name[sizeof(it->name) - 1] = '\0';
    it->status = 1;
    it->priority = prio;
}

void process_item(const char* name, int prio) {
    Item* item = (Item*)malloc(sizeof(Item));
    setup_item(item, name, prio);
    printf("item: %s prio=%d\n", item->name, item->priority);
    free(item);
}

int main() {
    process_item("task_01", 3);
    return 0;
}
