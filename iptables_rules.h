#include <libiptc/libiptc.h>

static int insert_rule (const char *table,
                 const char *chain, 
                 unsigned int src,
                 int inverted_src,
                 unsigned int dest,
                 int inverted_dst,
                 const char *target);