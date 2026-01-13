#ifndef TEST_H
#define TEST_H

#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static char current_test[256] = "";

#define TEST(name)                                                             \
    do {                                                                       \
        strncpy(current_test, name, sizeof(current_test) - 1);                 \
        current_test[sizeof(current_test) - 1] = '\0';                         \
        printf("[ RUN      ] %s\n", current_test);                             \
        tests_run++;                                                           \
        int _test_result = 0;

#define END_TEST                                                               \
    if (_test_result == 0) {                                                   \
        tests_passed++;                                                        \
        printf("[       OK ] %s\n", current_test);                             \
    } else {                                                                   \
        tests_failed++;                                                        \
    }                                                                          \
    }                                                                          \
    while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("          - %s: %s:%d\n", msg, __FILE__, __LINE__);            \
        _test_result = 1;                                                      \
    } while (0)

#define ASSERT_TRUE(cond)                                                      \
    do {                                                                       \
        if (!(cond)) {                                                         \
            FAIL(#cond " is false");                                           \
        }                                                                      \
    } while (0)

#define ASSERT_FALSE(cond)                                                     \
    do {                                                                       \
        if (cond) {                                                            \
            FAIL(#cond " is true");                                            \
        }                                                                      \
    } while (0)

#define ASSERT_INT_EQUAL(expected, actual)                                     \
    do {                                                                       \
        int _exp = (expected);                                                 \
        int _act = (actual);                                                   \
        if (_exp != _act) {                                                    \
            char _msg[256];                                                    \
            snprintf(_msg, sizeof(_msg), "Expected %d, got %d", _exp, _act);   \
            FAIL(_msg);                                                        \
        }                                                                      \
    } while (0)

#define ASSERT_INT_NOT_EQUAL(not_expected, actual)                             \
    do {                                                                       \
        int _nexp = (not_expected);                                            \
        int _act = (actual);                                                   \
        if (_nexp == _act) {                                                   \
            char _msg[256];                                                    \
            snprintf(_msg, sizeof(_msg), "Expected %d != %d", _act, _nexp);    \
            FAIL(_msg);                                                        \
        }                                                                      \
    } while (0)

#define ASSERT_STRING_EQUAL(expected, actual)                                  \
    do {                                                                       \
        const char *_exp = (expected);                                         \
        const char *_act = (actual);                                           \
        if (_exp == NULL || _act == NULL || strcmp(_exp, _act) != 0) {         \
            char _msg[256];                                                    \
            snprintf(                                                          \
                _msg, sizeof(_msg), "Expected \"%s\", got \"%s\"",             \
                _exp ? _exp : "(null)", _act ? _act : "(null)"                 \
            );                                                                 \
            FAIL(_msg);                                                        \
        }                                                                      \
    } while (0)

#define ASSERT_STRING_NOT_EQUAL(expected, actual)                              \
    do {                                                                       \
        const char *_exp = (expected);                                         \
        const char *_act = (actual);                                           \
        if (_exp != NULL && _act != NULL && strcmp(_exp, _act) == 0) {         \
            FAIL("Strings are equal but should not be");                       \
        }                                                                      \
    } while (0)

#define ASSERT_NON_NULL(ptr)                                                   \
    do {                                                                       \
        if ((ptr) == NULL) {                                                   \
            FAIL(#ptr " is NULL");                                             \
        }                                                                      \
    } while (0)

#define ASSERT_NULL(ptr)                                                       \
    do {                                                                       \
        if ((ptr) != NULL) {                                                   \
            FAIL(#ptr " is not NULL");                                         \
        }                                                                      \
    } while (0)

#define RUN_TESTS(...)                                                         \
    do {                                                                       \
        printf("[==========] Running tests.\n");                               \
        __VA_ARGS__                                                            \
        printf(                                                                \
            "[==========] Tests: %d run, %d passed, %d failed.\n", tests_run,  \
            tests_passed, tests_failed                                         \
        );                                                                     \
        return tests_failed > 0 ? 1 : 0;                                       \
    } while (0)

#endif
