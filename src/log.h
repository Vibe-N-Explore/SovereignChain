/* log.h - structured, one-line-per-event logging to stderr.
 *
 * Output format (key=value pairs, easy to grep and to parse later):
 *   ts=1761300000.123 level=info module=main node=2 msg=started role=normal port=9002
 *
 * Rules:
 *  - 'module' and 'msg' are short constant identifiers (no spaces).
 *  - Extra key=value details are passed through log_eventf's format string.
 *  - Newlines in details are replaced so one event is always one line.
 *  - Never pass private keys or secrets to the logger.
 */
#ifndef SC_LOG_H
#define SC_LOG_H

typedef enum { LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR } log_level_t;

/* Set the node id shown on every line. Use -1 while it is still unknown. */
void log_init(int node_id);

void log_event(log_level_t lvl, const char *module, const char *msg);

void log_eventf(log_level_t lvl, const char *module, const char *msg,
                const char *fmt, ...) __attribute__((format(printf, 4, 5)));

#endif /* SC_LOG_H */
