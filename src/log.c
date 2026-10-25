#define _POSIX_C_SOURCE 200809L
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int g_node_id = -1;

void log_init(int node_id) { g_node_id = node_id; }

static const char *level_str(log_level_t l)
{
    switch (l) {
    case LOG_DEBUG: return "debug";
    case LOG_INFO:  return "info";
    case LOG_WARN:  return "warn";
    case LOG_ERROR: return "error";
    }
    return "info";
}

/* Keep one event on one line: replace CR/LF in untrusted detail text. */
static void flatten(char *s)
{
    for (; *s; s++)
        if (*s == '\n' || *s == '\r')
            *s = ' ';
}

static void emit(log_level_t lvl, const char *module, const char *msg,
                 const char *extra)
{
    struct timespec ts;
    char nodepart[32] = "";
    char line[1100];

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        ts.tv_sec = 0;
        ts.tv_nsec = 0;
    }
    if (g_node_id >= 0)
        snprintf(nodepart, sizeof nodepart, " node=%d", g_node_id);

    /* Build the whole line (with '\n') first and write it with ONE call,
     * so lines from different processes do not get interleaved mid-line. */
    snprintf(line, sizeof line,
             "ts=%lld.%03ld level=%s module=%s%s msg=%s%s%s\n",
             (long long)ts.tv_sec, ts.tv_nsec / 1000000L, level_str(lvl),
             module, nodepart, msg, (extra && *extra) ? " " : "",
             extra ? extra : "");
    fputs(line, stderr);
}

void log_event(log_level_t lvl, const char *module, const char *msg)
{
    emit(lvl, module, msg, NULL);
}

void log_eventf(log_level_t lvl, const char *module, const char *msg,
                const char *fmt, ...)
{
    char extra[768];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(extra, sizeof extra, fmt, ap);
    va_end(ap);
    flatten(extra);
    emit(lvl, module, msg, extra);
}
