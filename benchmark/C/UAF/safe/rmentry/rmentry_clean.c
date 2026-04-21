#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct { int id; char label[32]; double score; } Record;

double compute_score(Record* r) {
    return r->id * 1.5;
}

double score_entry(int id, const char* label) {
    Record* r = (Record*)malloc(sizeof(Record));
    r->id = id;
    strncpy(r->label, label, sizeof(r->label) - 1);
    r->label[sizeof(r->label) - 1] = '\0';
    r->score = compute_score(r);
    double score = r->score;
    free(r);
    return score;
}

int main() {
    double s = score_entry(7, "eval");
    printf("score: %.1f\n", s);
    return 0;
}
