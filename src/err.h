/* err.h - error codes shared by all SovereignChain modules.
 *
 * Convention: functions that can fail return sc_err_t (SC_OK == 0).
 * Results are handed back through out-parameters, never through the
 * return value. Functions that parse untrusted/user text also take an
 * (errbuf, errlen) pair so they can say *why* they failed.
 */
#ifndef SC_ERR_H
#define SC_ERR_H

typedef enum {
    SC_OK = 0,
    SC_ERR_IO,        /* file/socket/OS failure                          */
    SC_ERR_PARSE,     /* text is not syntactically valid                 */
    SC_ERR_INVALID,   /* syntactically fine but violates a rule          */
    SC_ERR_NOT_FOUND  /* a required item does not exist                  */
} sc_err_t;

static inline const char *sc_err_str(sc_err_t e)
{
    switch (e) {
    case SC_OK:            return "ok";
    case SC_ERR_IO:        return "io_error";
    case SC_ERR_PARSE:     return "parse_error";
    case SC_ERR_INVALID:   return "invalid";
    case SC_ERR_NOT_FOUND: return "not_found";
    }
    return "unknown";
}

#endif /* SC_ERR_H */
