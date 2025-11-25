#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef ITERATIONS
#define ITERATIONS (2048)
#endif

/* C99 types */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L /* The compiler supports C99 */
#define SIZE_T_FMT "z"
#define SIZE_T_FMT_TYPE size_t
#define LONGLONG long long
#define LONGDOUBLE long double
#define LONGDOUBLE_FMT "L"
#elif defined(_MSC_VER) /* Some MSVC versions don't fully support C99 */
#define SIZE_T_FMT "I"
#define SIZE_T_FMT_TYPE size_t
#define LONGLONG __int64
#if _MSC_VER >= 1310
#define LONGDOUBLE long double
#define LONGDOUBLE_FMT "L"
#else
#define LONGDOUBLE double
#define LONGDOUBLE_FMT ""
#endif
#else
#define SIZE_T_FMT "l" /* Old compiler, use long */
#define SIZE_T_FMT_TYPE long
#if defined(__GNUC__) /* GCC supports long long as an extension */
#define LONGLONG long long
#else
#define LONGLONG long
#define __extension__ /* */
#endif
#define LONGDOUBLE double
#define powl pow
#define sqrtl sqrt
#define LONGDOUBLE_FMT ""
#endif
/* End C99 types */

/* Compatibility */
#if !defined(__has_attribute) /* Clang & newer GCC */
#define __has_attribute(x) 0
#endif /* !defined(__has_attribute) */

#if !defined(__has_builtin) /* Clang */
#define __has_builtin(x) 0
#endif /* !defined(__has_builtin) */

#if !defined(INFINITY)
#define INFINITY ((double) 1.0e120)
#endif

#if defined(_MSC_VER) /* MSVC-specific */
#define NOINLINE __declspec(noinline) /* MSVC extension */
#elif __has_attribute(__noinline__) || (defined(__GNUC__) && (__GNUC__ > 3) || (__GNUC__ == 3 && defined(__GNUC_MINOR__) && __GNUC_MINOR__ >= 1))
#define NOINLINE __attribute__ ((noinline)) /* GNU extension */
#else
#define NOINLINE /* not supported */
#endif /* defined(_MSC_VER) */

#if __has_builtin(__builtin_expect) || (defined(__GNUC__) && (__GNUC__ > 3) || (__GNUC__ == 3 && defined(__GNUC_MINOR__) && __GNUC_MINOR__ >= 1))
#define likely(x) __builtin_expect((x),1) /* GNU extension */
#else
#define likely(x) x
#endif /* __has_builtin(__builtin_expect) */

#if defined(_MSC_VER) /* MSVC inline assembler */
#if !defined(intel) /* Use LFENCE for Intel processors and MFENCE for other manufacturers */
#define xFENCE __asm _emit 0x0f __asm _emit 0xae __asm _emit 0xf0 /* MFENCE */
#else
#define xFENCE __asm _emit 0x0f __asm _emit 0xae __asm _emit 0xe8 /* LFENCE */
#endif
#define RDTSC rdtsc
#define RDTSCP rdtscp

#define WARMUP_MEASUREMENT() __asm { \
        xFENCE \
       __asm RDTSC \
        xFENCE \
        __asm RDTSC \
        xFENCE \
        __asm RDTSC \
        xFENCE \
}

#define START_MEASUREMENT(HI, LO) __asm { \
        xFENCE \
        __asm RDTSC \
        __asm mov LO,eax \
        __asm mov HI,edx \
}

#define END_MEASUREMENT(HI, LO) __asm { \
        __asm RDTSCP \
        xFENCE \
        __asm mov LO,eax \
        __asm mov HI,edx \
}

#define ZERO_REGISTER(OUT) __asm mov OUT,0
#elif defined(__GNUC__) /* GCC-style extended asm */
#if !defined(intel) /* Use LFENCE for Intel processors and MFENCE for other manufacturers */
#define xFENCE ".byte 0x0f, 0xae, 0xf0\n" /* MFENCE */
#else
#define xFENCE ".byte 0x0f, 0xae, 0xe8\n" /* LFENCE */
#endif
#define RDTSC ".byte 0x0f, 0x31\n"        /* RDTSC */
#define RDTSCP ".byte 0x0f, 0x01, 0xf9\n" /* RDTSCP */

#define WARMUP_MEASUREMENT() __asm__ volatile ( \
        xFENCE \
        RDTSC \
        xFENCE \
        RDTSC \
        xFENCE \
        RDTSC \
        xFENCE \
        : : : "%eax", "%edx", "memory" \
)

#define START_MEASUREMENT(HI, LO) __asm__ volatile ( \
        xFENCE \
        RDTSC \
        : "=d" (HI), "=a" (LO) : : "memory" \
)

#define END_MEASUREMENT(HI, LO) __asm__ volatile ( \
        RDTSCP \
        xFENCE \
        : "=d" (HI), "=a" (LO) : : "%ecx", "memory" \
)
#define ZERO_REGISTER(OUT) __asm__ volatile ("xor %0, %0" : "=r"(OUT) : : )
#else /* Unsupported compiler. */
#define WARMUP_MEASUREMENT() /* */
#define START_MEASUREMENT(HI, LO) HI = 0; LO = 0
#define END_MEASUREMENT(HI, LO) HI = 0; LO = 0
#define ZERO_REGISTER(OUT) OUT = 0
#endif /* defined(_MSC_VER) */

/* End Compatibility */

typedef unsigned LONGLONG u64;
typedef unsigned long u32;

/* Function signatures */
NOINLINE static int do_nothing(void);
NOINLINE static int do_something(void);
static void compute_statistics(u64 const data[], size_t const len, LONGDOUBLE * min, LONGDOUBLE * max, LONGDOUBLE * mean, LONGDOUBLE * variance);
/* End function signatures */

int do_nothing() {
    int r;

    ZERO_REGISTER(r);

    return r;
}

int do_something() {
    int r;

    ZERO_REGISTER(r);

    return r;
}

void compute_statistics(u64 const data[], size_t const len, LONGDOUBLE * const min, LONGDOUBLE * const max, LONGDOUBLE * const mean, LONGDOUBLE * const variance) {
    LONGDOUBLE sum1 = 0.0L, sum2 = 0.0L, mean_, variance_, min_ = (LONGDOUBLE)INFINITY, max_ = (LONGDOUBLE) -INFINITY;
    size_t i;

    for (i = 0; i < len; i++) {
        LONGDOUBLE const t = (LONGDOUBLE) data[i];
        sum1 += t;
        if (t > max_) max_ = t;
        if (t < min_) min_ = t;
    }

    mean_ = sum1 / (LONGDOUBLE) len;

    for (i = 0; i < len; i++) {
        sum2 += powl((LONGDOUBLE)data[i] - mean_, 2);
    }

    variance_ = sum2 / (((LONGDOUBLE)len) - 1.0L);

    if (NULL != min) *min = min_;
    if (NULL != max) *max = max_;
    if (NULL != mean) *mean = mean_;
    if (NULL != variance) *variance = variance_;
}

int main(int argc, char **argv) {
    int ret = 0;
    size_t j, k;
    u64 * deltas;
    LONGDOUBLE min, max, mean, variance;
    u32 cycles_low_s, cycles_high_s, cycles_low_e, cycles_high_e;
    u64 start, end;

    (void)argc;
    (void)argv;

    deltas = (u64 *) malloc(sizeof(*deltas) * ITERATIONS);

    WARMUP_MEASUREMENT();

    /* Nothing */
    {
        printf("[%s] Starting benchmark\n", "NULL");
        for(j = 0, k = 0; j < ITERATIONS; j++) {
            START_MEASUREMENT(cycles_high_s, cycles_low_s);
            ret = do_nothing();
            if (likely(0 == ret)) {
                END_MEASUREMENT(cycles_high_e, cycles_low_e);
                start = ( ((u64) cycles_high_s << 040) | cycles_low_s );
                end   = ( ((u64) cycles_high_e << 040) | cycles_low_e );
                deltas[k++] = end - start;
            } else {
                fprintf(stderr, "Unexpected error occurred benchmarking type %s.\n", "NULL");
                printf("[%s] ERROR\n", "NULL");
            }
        }
        compute_statistics(deltas, k, &min, &max, &mean, &variance);
        printf("[%s]\t [%" LONGDOUBLE_FMT "e - %" LONGDOUBLE_FMT "e] mean: %" LONGDOUBLE_FMT "e (std. dev.: %" LONGDOUBLE_FMT "e) N:%" SIZE_T_FMT "u\n", "NULL", min, max, mean, sqrtl(variance), (SIZE_T_FMT_TYPE)k);
    }

    /* Something */
    {
        printf("[%s] Starting benchmark\n", "NULL");
        for(j = 0, k = 0; j < ITERATIONS; j++) {
            START_MEASUREMENT(cycles_high_s, cycles_low_s);
            ret = do_something();
            if (likely(0 == ret)) {
                END_MEASUREMENT(cycles_high_e, cycles_low_e);
                start = ( ((u64) cycles_high_s << 040) | cycles_low_s );
                end   = ( ((u64) cycles_high_e << 040) | cycles_low_e );
                deltas[k++] = end - start;
            } else {
                fprintf(stderr, "Unexpected error occurred benchmarking type %s.\n", "NULL");
                printf("[%s] ERROR\n", "NULL");
            }
        }
        compute_statistics(deltas, k, &min, &max, &mean, &variance);
        printf("[%s]\t [%" LONGDOUBLE_FMT "e - %" LONGDOUBLE_FMT "e] mean: %" LONGDOUBLE_FMT "e (std. dev.: %" LONGDOUBLE_FMT "e) N:%" SIZE_T_FMT "u\n", "NULL", min, max, mean, sqrtl(variance), (SIZE_T_FMT_TYPE)k);
    }

    free(deltas);

    return !!ret;
}