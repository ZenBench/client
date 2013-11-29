/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2004,2006 by Solar Designer
 */

/*
 * 15.02.08 Elli0t: fixed get_cps; benchmark_all: double -> long;
 *                  added: format_cps, print_cps.
 */

#ifdef __ultrix__
#define __POSIX
#define _POSIX_SOURCE
#endif

#ifdef _SCO_C_DIALECT
#include <limits.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>

#include "times.h"

#include "arch.h"
#include "misc.h"
#include "math.h"
#include "params.h"
#include "memory.h"
#include "signals.h"
#include "formats.h"
#include "bench.h"

#include "mpi.h"
#include "ryan.h"

long clk_tck = 0;

void clk_tck_init(void)
{
  if (clk_tck) return;
#if defined(_SC_CLK_TCK) || !defined(CLK_TCK)
  clk_tck = sysconf(_SC_CLK_TCK);
#else
  clk_tck = CLK_TCK;
#endif
}

static volatile int bench_running;

static void bench_handle_timer(int signum)
{
        bench_running = 0;
}

static void bench_set_keys(struct fmt_main *format,
        struct fmt_tests *current, int cond)
{
        char *plaintext;
        int index, length;

        format->methods.clear_keys();

        length = format->params.benchmark_length;
        for (index = 0; index < format->params.max_keys_per_crypt; index++) {
                do {
                        if (!current->ciphertext)
                                current = format->params.tests;
                        plaintext = current->plaintext;
                        current++;

                        if (cond > 0) {
                                if ((int)strlen(plaintext) > length) break;
                        } else
                        if (cond < 0) {
                                if ((int)strlen(plaintext) <= length) break;
                        } else
                                break;
                } while (1);

                format->methods.set_key(plaintext, index);
        }
}

char *benchmark_format(struct fmt_main *format, int salts,
        struct bench_results *results)
{
        static void *binary = NULL;
        static int binary_size = 0;
        static char s_error[64];
        char *where;
        struct fmt_tests *current;
        int cond;
#if OS_TIMER
        struct itimerval it;
#endif
        struct tms buf;
        clock_t start_real, start_virtual, end_real, end_virtual;
        unsigned ARCH_WORD count;
        char *ciphertext;
        void *salt, *two_salts[2];
        int index, max;

        clk_tck_init();

        if (!(current = format->params.tests)) return "FAILED (no data)";
        if ((where = fmt_self_test(format))) {
                sprintf(s_error, "FAILED (%s)", where);
                return s_error;
        }

        if (format->params.binary_size > binary_size) {
                binary_size = format->params.binary_size;
                binary = mem_alloc_tiny(binary_size, MEM_ALIGN_WORD);
                memset(binary, 0x55, binary_size);
        }

        for (index = 0; index < 2; index++) {
                two_salts[index] = mem_alloc(format->params.salt_size);

                if ((ciphertext = format->params.tests[index].ciphertext))
                        salt = format->methods.salt(ciphertext);
                else
                        salt = two_salts[0];

                memcpy(two_salts[index], salt, format->params.salt_size);
        }

        if (format->params.benchmark_length > 0) {
                cond = (salts == 1) ? 1 : -1;
                salts = 1;
        } else
                cond = 0;

        bench_set_keys(format, current, cond);

#if OS_TIMER
        memset(&it, 0, sizeof(it));
        if (setitimer(ITIMER_REAL, &it, NULL)) pexit("setitimer");
#endif

        bench_running = 1;
        signal(SIGALRM, bench_handle_timer);

#if OS_TIMER
        it.it_value.tv_sec = BENCHMARK_TIME;
        if (setitimer(ITIMER_REAL, &it, NULL)) pexit("setitimer");
#else
        sig_timer_emu_init(BENCHMARK_TIME * clk_tck);
#endif

        start_real = times(&buf);
        start_virtual = buf.tms_utime + buf.tms_stime;
        count = 0;

        index = salts;
        max = format->params.max_keys_per_crypt;
        do {
                if (!--index) {
                        index = salts;
                        if (!(++current)->ciphertext)
                                current = format->params.tests;
                        bench_set_keys(format, current, cond);
                }

                if (salts > 1) format->methods.set_salt(two_salts[index & 1]);
                format->methods.crypt_all(max);
                format->methods.cmp_all(binary, max);

                count++;
#if !OS_TIMER
                sig_timer_emu_tick();
#endif
        } while (bench_running && !event_abort);

        end_real = times(&buf);
        end_virtual = buf.tms_utime + buf.tms_stime;
        if (end_virtual == start_virtual) end_virtual++;

        results->real = end_real - start_real;
        results->virtual = end_virtual - start_virtual;
        results->count = count * max;

        for (index = 0; index < 2; index++)
                MEM_FREE(two_salts[index]);

        return event_abort ? "" : NULL;
}

void benchmark_cps(unsigned ARCH_WORD count, clock_t time, char *buffer)
{
        unsigned int cps_hi, cps_lo;
        int64 tmp;

        tmp.lo = count; tmp.hi = 0;
        mul64by32(&tmp, clk_tck);
        cps_hi = div64by32lo(&tmp, time);

        if (cps_hi >= 1000000)
                sprintf(buffer, "%uK", cps_hi / 1000);
        else
        if (cps_hi >= 100)
                sprintf(buffer, "%u", cps_hi);
        else {
                mul64by32(&tmp, 10);
                cps_lo = div64by32lo(&tmp, time) % 10;
                sprintf(buffer, "%u.%u", cps_hi, cps_lo);
        }
}


/* RYAN */
long get_cps( unsigned ARCH_WORD count, clock_t time )
{
  unsigned int cps_hi;
  int64 tmp;
  tmp.lo = count;
  tmp.hi = 0;
  mul64by32( &tmp, clk_tck );
  cps_hi = div64by32lo( &tmp, time );
  return( cps_hi );
}

void format_cps( char *buffer, long cps )
{
  if ( cps >= 1000000 )
    sprintf( buffer, "%ldK", cps / 1000 );
  else
    sprintf( buffer, "%ld", cps );
}

void print_cps( const char *msg, long cps_r, long cps_v, char *ciphername, char *cipherinfo)
{
  char buf_r[20], buf_v[20];
  format_cps( buf_r, cps_r );
  format_cps( buf_v, cps_v );
#if !defined(__DJGPP__) && !defined(__CYGWIN32__) && !defined(__BEOS__)
  printf( "%s%s:%s:\t%s c/s real, %s c/s virtual\n",
	  ciphername,cipherinfo,msg, buf_r, buf_v );
#else
  printf( "%s%s:%s:\t%s c/s\n",
	  ciphername,cipherinfo,msg, buf_r );
#endif
  printf( "\n" );
  fflush( stdout );
}

void benchmark_all(void)
{
        struct fmt_main *format;
        char *result, *msg_1, *msg_m;
        struct bench_results results_1, results_m;
	/* char s_real[64], s_virtual[64]; */

        /* RYAN */
        long global_rcs_m=0, global_vcs_m=0;
	long local_rcs_m=0, local_vcs_m=0;
	long global_rcs_1=0, global_vcs_1=0;
	long local_rcs_1=0, local_vcs_1=0;
        global_rcs_m = 0;
        global_vcs_m = 0;
        global_rcs_1 = 0;
        global_vcs_1 = 0;

	if ((format = fmt_list))
        do {
                if(mpi_id == 0) {
                        printf("Benchmarking: %s%s [%s]... \n",
                                        format->params.format_name,
                                        format->params.benchmark_comment,
                                        format->params.algorithm_name);
                        //THE//fflush(stdout);
                }

                switch (format->params.benchmark_length) {
                case -1:
                        msg_m = "Raw";
                        msg_1 = NULL;
                        break;

                case 0:
                        msg_m = "Many salts";
                        msg_1 = "Only one salt";
                        break;

                default:
                        msg_m = "Short";
                        msg_1 = "Long";
                }

                if ((result = benchmark_format(format,
                                                format->params.salt_size ? BENCHMARK_MANY : 1,
                                                &results_m))) {
                        if(mpi_id == 0) {
                                printf("RESULT:%s-%s:%s \n",format->params.format_name,format->params.benchmark_comment,result);
                        }
                        continue;
                }

		if (msg_1)
                if ((result = benchmark_format(format, 1, &results_1))) {
                        if(mpi_id == 0) {
                                printf("RESULT:%s-%s:%s \n",format->params.format_name,format->params.benchmark_comment,result);
                        }
                        continue;
                }

                if(mpi_id == 0) {
                        printf("%s \n","DONE");
                }

                local_rcs_m = get_cps(results_m.count, results_m.real);
                MPI_Reduce(&local_rcs_m, &global_rcs_m, 1, MPI_LONG,
                        MPI_SUM, 0, MPI_COMM_WORLD);
                local_vcs_m = get_cps(results_m.count, results_m.virtual);
                MPI_Reduce(&local_vcs_m, &global_vcs_m, 1, MPI_LONG,
                        MPI_SUM, 0, MPI_COMM_WORLD);

                if ( mpi_id == 0 ){
		  print_cps( msg_m, global_rcs_m, global_vcs_m,format->params.format_name,format->params.benchmark_comment );
                }

		/*
                benchmark_cps(results_m.count, results_m.real, s_real);
                benchmark_cps(results_m.count, results_m.virtual, s_virtual);
#if !defined(__DJGPP__) && !defined(__CYGWIN32__) && !defined(__BEOS__)
                printf("%s:\t%s c/s real, %s c/s virtual\n",
                        msg_m, s_real, s_virtual);
#else
                printf("%s:\t%s c/s\n",
                        msg_m, s_real);
#endif
		*/

                if (!msg_1) {
                        if(mpi_id == 0) {
                                putchar('\n');
                        }
                        continue;
                }

                local_rcs_1 = get_cps(results_1.count, results_1.real);
                MPI_Reduce(&local_rcs_1, &global_rcs_1, 1, MPI_LONG,
                        MPI_SUM, 0, MPI_COMM_WORLD);
                local_vcs_1 = get_cps(results_1.count, results_1.virtual);
                MPI_Reduce(&local_vcs_1, &global_vcs_1, 1, MPI_LONG,
                        MPI_SUM, 0, MPI_COMM_WORLD);

                if ( mpi_id == 0 ){
		  print_cps( msg_1, global_rcs_1, global_vcs_1,format->params.format_name,format->params.benchmark_comment );
                }

		/*
                benchmark_cps(results_1.count, results_1.real, s_real);
                benchmark_cps(results_1.count, results_1.virtual, s_virtual);
#if !defined(__DJGPP__) && !defined(__CYGWIN32__) && !defined(__BEOS__)
                printf("%s:\t%s c/s real, %s c/s virtual\n\n",
                        msg_1, s_real, s_virtual);
#else
                printf("%s:\t%s c/s\n\n",
                        msg_1, s_real);
#endif
		*/
	fflush(stdout); 
        } while ((format = format->next) && !event_abort);
}
