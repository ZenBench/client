/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2004,2006 by Solar Designer
 */

#include "mpi.h"
#include "ryan.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "list.h"
#include "tty.h"
#include "signals.h"
#include "common.h"
#include "formats.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "options.h"
#include "config.h"
#include "bench.h"
#include "charset.h"
#include "single.h"
#include "wordlist.h"
#include "inc.h"
#include "external.h"
#include "batch.h"
#include "ciphers.h"

#if CPU_DETECT
extern int CPU_detect(void);
#endif

extern struct fmt_main fmt_DES, fmt_BSDI, fmt_MD5, fmt_BF;
extern struct fmt_main fmt_AFS, fmt_LM, fmt_rawMD5, fmt_NT;
extern struct fmt_main fmt_MD5_apache;
extern struct fmt_main fmt_BFEgg;
extern struct fmt_main fmt_MYSQL;
extern struct fmt_main fmt_NSLDAP;
extern struct fmt_main fmt_NSLDAPS;
extern struct fmt_main fmt_lotus5;
extern struct fmt_main fmt_mscash;
extern struct fmt_main fmt_rawSHA1;
extern struct fmt_main fmt_mssql;
extern struct fmt_main fmt_hmacMD5;
extern struct fmt_main fmt_WPAPSK;
extern struct fmt_main fmt_oracle;
extern struct fmt_main fmt_IPB2;

#ifdef MMX_COEF
#ifndef OSX
extern struct fmt_main fmt_NTmmx;
#endif
#endif

extern int unshadow(int argc, char **argv);
extern int unafs(int argc, char **argv);
extern int unique(int argc, char **argv);
extern int undrop(int argc, char **argv);

static struct db_main database;
static struct fmt_main dummy_format;


static void john_register_one(struct fmt_main *format)
{
	if (options.format)
	if (strcmp(options.format, format->params.label)) return;

	fmt_register(format);
}

static void john_register_all(void)
{
	if (options.format) strlwr(options.format);

#ifdef CIPHER_DES
	john_register_one(&fmt_DES);
#endif
#ifdef CIPHER_BSDI
	john_register_one(&fmt_BSDI);
#endif
#ifdef CIPHER_MD5
	john_register_one(&fmt_MD5);
#endif
#ifdef CIPHER_BLOWFISH
	john_register_one(&fmt_BF);
#endif
#ifdef CIPHER_KERBEROS_AFS
	john_register_one(&fmt_AFS);
#endif
#ifdef CIPHER_LANMAN
	john_register_one(&fmt_LM);
#endif
	//new ciphers
#ifdef CIPHER_MD5_APACHE
	john_register_one(&fmt_MD5_apache);
#endif
#ifdef CIPHER_MYSQL
	john_register_one(&fmt_MYSQL);
#endif
#ifdef CIPHER_NETSCAPE_LDAP
	john_register_one(&fmt_NSLDAP);
#endif
#ifdef CIPHER_NTLM
#ifdef MMX_COEF
#ifndef OSX
	john_register_one(&fmt_NTmmx);
#else
	john_register_one(&fmt_NT);
#endif
#else
	john_register_one(&fmt_NT);
#endif

#endif
#ifdef CIPHER_LOTUS
	john_register_one(&fmt_lotus5);
#endif
#ifdef CIPHER_MSCACHE
	john_register_one(&fmt_mscash);
#endif
#ifdef CIPHER_RAWMD5
	john_register_one(&fmt_rawMD5);
#endif
#ifdef CIPHER_IPB2
	john_register_one(&fmt_IPB2);
#endif
#ifdef CIPHER_EGGDROP
	john_register_one(&fmt_BFEgg);
#endif
#ifdef CIPHER_SHA1
	john_register_one(&fmt_rawSHA1);
#endif
#ifdef CIPHER_MSSQL
	john_register_one(&fmt_mssql);
#endif
#ifdef CIPHER_HMACMD5
	john_register_one(&fmt_hmacMD5);
#endif
#ifdef CIPHER_WPAPSK
	john_register_one(&fmt_WPAPSK);
#endif
#ifdef CIPHER_ORACLE
	john_register_one(&fmt_oracle);
#endif

#ifdef CIPHER_NSLDAPS
	john_register_one(&fmt_NSLDAPS);
#endif
	if (!fmt_list) {
		fprintf(stderr, "Unknown ciphertext format name requested\n");
		error();
	}
}

static void john_log_format(void)
{
	int min_chunk, chunk;

	log_event("- Hash type: %.100s (lengths up to %d%s)",
		database.format->params.format_name,
		database.format->params.plaintext_length,
		database.format->methods.split != fmt_default_split ?
		", longer passwords split" : "");

	log_event("- Algorithm: %.100s",
		database.format->params.algorithm_name);

	chunk = min_chunk = database.format->params.max_keys_per_crypt;
	if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK) &&
	    chunk < SINGLE_HASH_MIN)
			chunk = SINGLE_HASH_MIN;
	if (chunk > 1)
		log_event("- Candidate passwords %s be buffered and "
			"tried in chunks of %d",
			min_chunk > 1 ? "will" : "may",
			chunk);
}

static char *john_loaded_counts(void)
{
	static char s_loaded_counts[80];

	if (database.password_count == 1)
		return "1 password hash";

	sprintf(s_loaded_counts,
		database.salt_count > 1 ?
		"%d password hashes with %d different salts" :
		"%d password hashes with no different salts",
		database.password_count,
		database.salt_count);

	return s_loaded_counts;
}

static void john_load(void)
{
	struct list_entry *current;
	char *log__name, *pot__name;

	log__name = malloc(sizeof(char) * 25);
	pot__name = malloc(sizeof(char) * 25);

	strcpy(log__name, LOG_NAME);
	strcpy(pot__name, POT_NAME);

	umask(077);

	if (options.flags & FLG_EXTERNAL_CHK)
		ext_init(options.external);

	if (options.flags & FLG_MAKECHR_CHK) {
		options.loader.flags |= DB_CRACKED;
		ldr_init_database(&database, &options.loader);

		if (options.flags & FLG_PASSWD) {
			ldr_show_pot_file(&database, pot__name);

			database.options->flags |= DB_PLAINTEXTS;
			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));
		} else {
			database.options->flags |= DB_PLAINTEXTS;
			ldr_show_pot_file(&database, pot__name);
		}

		return;
	}

	if (options.flags & FLG_STDOUT) {
		ldr_init_database(&database, &options.loader);
		database.format = &dummy_format;
		memset(&dummy_format, 0, sizeof(dummy_format));
		dummy_format.params.plaintext_length = options.length;
		dummy_format.params.flags = FMT_CASE | FMT_8_BIT;
	}

	if (options.flags & FLG_PASSWD) {
		if (options.flags & FLG_SHOW_CHK) {
			options.loader.flags |= DB_CRACKED;
			ldr_init_database(&database, &options.loader);

			ldr_show_pot_file(&database, pot__name);

			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));

			printf("%s%d password hash%s cracked, %d left\n",
				database.guess_count ? "\n" : "",
				database.guess_count,
				database.guess_count != 1 ? "es" : "",
				database.password_count -
				database.guess_count);

			return;
		}

		if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK))
			options.loader.flags |= DB_WORDS;
		else
		if (mem_saving_level)
			options.loader.flags &= ~DB_LOGIN;
		ldr_init_database(&database, &options.loader);

		if ((current = options.passwd->head))
		do {
			ldr_load_pw_file(&database, current->data);
		} while ((current = current->next));

		if ((options.flags & FLG_CRACKING_CHK) &&
		    database.password_count) {
			log_init(log__name, NULL, options.session);
			if (status_restored_time)
				log_event("Continuing an interrupted session");
			else
				log_event("Starting a new session");
			log_event("Loaded a total of %s", john_loaded_counts());
		}

		ldr_load_pot_file(&database, pot__name);

		ldr_fix_database(&database);

		if (database.password_count) {
			log_event("Remaining %s", john_loaded_counts());
			printf("Loaded %s (%s [%s])\n",
				john_loaded_counts(),
				database.format->params.format_name,
				database.format->params.algorithm_name);
		} else {
			log_discard();
			puts("No password hashes loaded");
		}

		if ((options.flags & FLG_PWD_REQ) && !database.salts) {
			MPI_Finalize();
			exit(0);
		}
	}
}

static void john_init(char *name, int argc, char **argv)
{
#if CPU_DETECT
	int detected;

	switch ((detected = CPU_detect())) {
#if CPU_REQ
	case 0:
#if CPU_FALLBACK
#if defined(__DJGPP__) || defined(__CYGWIN32__)
#error CPU_FALLBACK is incompatible with the current DOS and Win32 code
#endif
	case 2:
		execv(JOHN_SYSTEMWIDE_EXEC "/" CPU_FALLBACK_BINARY, argv);
		perror("execv: " JOHN_SYSTEMWIDE_EXEC "/" CPU_FALLBACK_BINARY);
#endif
		if (!detected)
			fprintf(stderr, "Sorry, %s is required\n", CPU_NAME);
		error();
#endif
	default:
		break;
	}
#endif

	path_init(argv);

#if JOHN_SYSTEMWIDE
	cfg_init(CFG_PRIVATE_FULL_NAME, 1);
	cfg_init(CFG_PRIVATE_ALT_NAME, 1);
#endif
	cfg_init(CFG_FULL_NAME, 1);
	cfg_init(CFG_ALT_NAME, 0);

	status_init(NULL, 1);
	opt_init(name, argc, argv);

	john_register_all();
	common_init();

	sig_init();

	john_load();
}

static void john_run(void)
{
	char *log__name, *pot__name;

	log__name = malloc(sizeof(char) * 25);
	pot__name = malloc(sizeof(char) * 25);

	strcpy(log__name, LOG_NAME);
	strcpy(pot__name, POT_NAME);
	
	if (options.flags & FLG_TEST_CHK)
		benchmark_all();
	else
	if (options.flags & FLG_MAKECHR_CHK)
		do_makechars(&database, options.charset);
	else
	if (options.flags & FLG_CRACKING_CHK) {
		if (!(options.flags & FLG_STDOUT)) {
			status_init(NULL, 1);
			log_init(log__name, pot__name, options.session);
			john_log_format();
			if (cfg_get_bool(SECTION_OPTIONS, NULL, "Idle"))
				log_event("- Configured to use otherwise idle "
					"processor cycles only");
		}
		tty_init();

		if (options.flags & FLG_SINGLE_CHK)
			do_single_crack(&database);
		else
		if (options.flags & FLG_WORDLIST_CHK)
			do_wordlist_crack(&database, options.wordlist,
				(options.flags & FLG_RULES) != 0);
		else
		if (options.flags & FLG_INC_CHK)
			do_incremental_crack(&database, options.charset);
		else
		if (options.flags & FLG_EXTERNAL_CHK)
			do_external_crack(&database);
		else
		if (options.flags & FLG_BATCH_CHK)
			do_batch_crack(&database);

		status_print();
		tty_done();
	}
}

static void john_done(void)
{
	path_done();

	if ((options.flags & FLG_CRACKING_CHK) &&
	    !(options.flags & FLG_STDOUT)) {
		if (event_abort)
			log_event("Session aborted");
		else
			log_event("Session completed");
	}
	log_done();
	check_abort(0);
}

int main(int argc, char **argv)
{
	char *name;
	MPI_Init(&argc, &argv);

	MPI_Comm_rank(MPI_COMM_WORLD, &mpi_id);
	MPI_Comm_size(MPI_COMM_WORLD, &mpi_p);

#ifdef __DJGPP__
	if (--argc <= 0) return 1;
	if ((name = strrchr(argv[0], '/')))
		strcpy(name + 1, argv[1]);
	name = argv[1];
	argv[1] = argv[0];
	argv++;
#else
	if (!argv[0])
		name = "john";
	else
	if ((name = strrchr(argv[0], '/')))
		name++;
	else
		name = argv[0];
#endif

#ifdef __CYGWIN32__
	strlwr(name);
	if (strlen(name) > 4 && !strcmp(name + strlen(name) - 4, ".exe"))
		name[strlen(name) - 4] = 0;
#endif

	if (!strcmp(name, "unshadow")) {
		MPI_Finalize();
		return unshadow(argc, argv);
	}

	if (!strcmp(name, "unafs")) {
		MPI_Finalize();
		return unafs(argc, argv);
	}

	if (!strcmp(name, "unique")) {
		MPI_Finalize();
		return unique(argc, argv);
	}

	if (!strcmp(name, "undrop"))
		return undrop(argc, argv);

	john_init(name, argc, argv);
	john_run();
	john_done();

	MPI_Finalize();

	return 0;
}
