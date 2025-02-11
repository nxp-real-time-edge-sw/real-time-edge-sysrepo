
#ifndef __LOG_H_
#define __LOG_H_

typedef enum {
    LOG_LEVEL_ERR,
    LOG_LEVEL_WRN,
    LOG_LEVEL_INF,
    LOG_LEVEL_DBG
} log_level_t;


#define LOG_ERR(...)    log_output(LOG_LEVEL_ERR, __VA_ARGS__)
#define LOG_WRN(...)    log_output(LOG_LEVEL_WRN, __VA_ARGS__)
#define LOG_INF(...)    log_output(LOG_LEVEL_INF, __VA_ARGS__)
#define LOG_DBG(...)    log_output(LOG_LEVEL_DBG, __VA_ARGS__)


void log_set_output_level(log_level_t level);
void log_output(log_level_t level, const char *format, ...);
void print_node_tree_xml(const struct lyd_node *node);

#endif
