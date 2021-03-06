/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2005,2006 by Solar Designer
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <errno.h>
#include <string.h>
#include "mpi.h"
#include "ryan.h"

#if defined(__CYGWIN32__) && !defined(__CYGWIN__)
extern int ftruncate(int fd, size_t length);
#endif

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "options.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"

char *rec_name = RECOVERY_NAME;
/* static int rec_name_fixed = 0; */
int rec_version = 0;
int rec_argc = 0;
char **rec_argv;
unsigned int rec_check;
int rec_restoring_now = 0;

static int rec_fd;
static FILE *rec_file = NULL;
static struct db_main *rec_db;
static void (*rec_save_mode)(FILE *file);

/*
char *id2string();

char *id2string() {
	char *temp_name = (char*) malloc(sizeof(char)*10);
	sprintf(temp_name, "%d", mpi_id);
	return temp_name;
}
*/

static char *rec_name_complete(char *rec_name)
{
       char *result;
 
       /*if (strchr(rec_name, '.')) return rec_name; */
 
       result = mem_alloc_tiny(strlen(rec_name) +
                strlen(RECOVERY_SUFFIX) +
                strlen(id2string()) +
                + 2, MEM_ALIGN_NONE);
       strcpy(result, rec_name);
       strcat(result, RECOVERY_SUFFIX);
       strcat(result, ".");
       strcat(result, id2string());

        /* fprintf(stderr, "result = %s\n\n", result); */

        return result;
}

#if defined(LOCK_EX) && OS_FLOCK
static void rec_lock(void)
{
	if (flock(rec_fd, LOCK_EX | LOCK_NB)) {
		if (errno == EWOULDBLOCK) {
			fprintf(stderr, "Crash recovery file is locked by process %d: %s\n",
				mpi_id,
				path_expand(rec_name));
			error();
		} else
			pexit("flock");
	}
}
#else
#define rec_lock() \
	{}
#endif

void rec_init(struct db_main *db, void (*save_mode)(FILE *file))
{
	rec_done(1);

	if (!rec_argc) return;

	/*if (!rec_name_fixed) */
	rec_name = rec_name_complete(rec_name);

	if ((rec_fd = open(path_expand(rec_name), O_RDWR | O_CREAT, 0600)) < 0)
		pexit("open: %s", path_expand(rec_name));
	rec_lock();
	if (!(rec_file = fdopen(rec_fd, "w"))) pexit("fdopen");

	rec_db = db;
	rec_save_mode = save_mode;
}

void rec_save(void)
{
	int save_format;
	long size;
	char **opt;

	log_flush();

	if (!rec_file) return;

	if (fseek(rec_file, 0, SEEK_SET)) pexit("fseek");
#ifdef __CYGWIN32__
	if (ftruncate(rec_fd, 0)) pexit("ftruncate");
#endif

	save_format = !options.format && rec_db->loaded;

	fprintf(rec_file, RECOVERY_V "\n%d\n",
		rec_argc + (save_format ? 1 : 0));

	opt = rec_argv;
	while (*++opt)
		fprintf(rec_file, "%s\n", *opt);

	if (save_format)
		fprintf(rec_file, "--format=%s\n",
			rec_db->format->params.label);

	fprintf(rec_file, "%u\n%u\n%08x\n%08x\n%d\n%d\n%08x\n",
		status_get_time() + 1,
		status.guess_count,
		status.crypts.lo,
		status.crypts.hi,
		status.pass,
		status_get_progress ? status_get_progress() : -1,
		rec_check);

	if (rec_save_mode) rec_save_mode(rec_file);

	if (ferror(rec_file)) pexit("fprintf");

	if ((size = ftell(rec_file)) < 0) pexit("ftell");
	if (fflush(rec_file)) pexit("fflush");
	if (ftruncate(rec_fd, size)) pexit("ftruncate");
#ifndef __CYGWIN32__
	if (fsync(rec_fd)) pexit("fsync");
#endif
}

void rec_done(int save)
{
	if (!rec_file) return;

	if (save)
		rec_save();
	else
		log_flush();

	if (fclose(rec_file)) pexit("fclose");
	rec_file = NULL;

	if (!save && unlink(path_expand(rec_name))) {
		//strcat(rec_name, id2string());
		rec_name = rec_name_complete(RECOVERY_NAME);
		if (unlink(path_expand(rec_name)))
			pexit("unlink: %s", path_expand(rec_name));
	}
}

static void rec_format_error(char *fn)
{
	rec_name = rec_name_complete(RECOVERY_NAME);
	if (ferror(rec_file))
		pexit(fn);
	else {
		fprintf(stderr, "Incorrect crash recovery file format: %s\n",
			path_expand(rec_name));
		error();
	}
}

void rec_restore_args(int lock)
{
	char line[LINE_BUFFER_SIZE];
	int index, argc;
	char **argv;
	char *save_rec_name;

	rec_name = rec_name_complete(RECOVERY_NAME);
	if (!(rec_file = fopen(path_expand(rec_name), "r+"))) {
		save_rec_name = rec_name;
		rec_name = rec_name_complete(rec_name);
		if (rec_name != save_rec_name)
			rec_file = fopen(path_expand(rec_name), "r+");
		if (!rec_file)
			pexit("fopen: %s", path_expand(rec_name));
	}
	rec_fd = fileno(rec_file);
	/* rec_name_fixed = 1; */

	if (lock) rec_lock();

	if (!fgetl(line, sizeof(line), rec_file)) rec_format_error("fgets");

	rec_version = 0;
	if (!strcmp(line, RECOVERY_V3)) rec_version = 3; else
	if (!strcmp(line, RECOVERY_V2)) rec_version = 2; else
	if (!strcmp(line, RECOVERY_V1)) rec_version = 1; else
	if (strcmp(line, RECOVERY_V0)) rec_format_error("fgets");

	if (fscanf(rec_file, "%d\n", &argc) != 1 || argc < 2)
		rec_format_error("fscanf");
	argv = mem_alloc_tiny(sizeof(char *) * (argc + 1), MEM_ALIGN_WORD);

	argv[0] = "john";

	for (index = 1; index < argc; index++)
	if (fgetl(line, sizeof(line), rec_file))
		argv[index] = str_alloc_copy(line);
	else
		rec_format_error("fgets");

	argv[argc] = NULL;

	save_rec_name = rec_name;
	opt_init(argv[0], argc, argv);
	rec_name = save_rec_name;

	if (fscanf(rec_file, "%u\n%u\n%x\n%x\n",
		&status_restored_time,
		&status.guess_count,
		&status.crypts.lo,
		&status.crypts.hi) != 4) rec_format_error("fscanf");
	if (!status_restored_time) status_restored_time = 1;

	if (rec_version == 0) {
		status.pass = 0;
		status.progress = -1;
	} else
	if (fscanf(rec_file, "%d\n%d\n", &status.pass, &status.progress) != 2)
		rec_format_error("fscanf");

	if (rec_version < 3)
		rec_check = 0;
	else
	if (fscanf(rec_file, "%x\n", &rec_check) != 1)
		rec_format_error("fscanf");

	rec_restoring_now = 1;
}

void rec_restore_mode(int (*restore_mode)(FILE *file))
{
	if (!rec_file) return;

	if (restore_mode)
	if (restore_mode(rec_file)) rec_format_error("fscanf");

	if (fclose(rec_file)) pexit("fclose");
	rec_file = NULL;

	rec_restoring_now = 0;
}
