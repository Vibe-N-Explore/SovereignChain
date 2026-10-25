/* testutil.h - Tiny test harness for connector unit tests. */
#ifndef CN_TESTUTIL_H
#define CN_TESTUTIL_H

#include <stdio.h>
#include <string.h>

static int t_checks = 0, t_failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        t_checks++;                                                          \
        if (!(cond)) {                                                       \
            t_failures++;                                                    \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                    \
    } while (0)

#define CHECK_CONTAINS(hay, needle) CHECK(strstr((hay), (needle)) != NULL)

#define RUN(fn)                                                              \
    do {                                                                     \
        int before = t_failures;                                             \
        fn();                                                                \
        printf("  %s %s\n", t_failures == before ? "ok  " : "FAIL", #fn);    \
    } while (0)

#define TEST_SUMMARY()                                                       \
    (printf("%d checks, %d failed\n", t_checks, t_failures),                 \
     t_failures == 0 ? 0 : 1)

#endif /* CN_TESTUTIL_H */
