/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2005 by Solar Designer
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "math.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "list.h"
#include "crc32.h"
#include "signals.h"
#include "loader.h"
#include "external.h"
#include "charset.h"

#include "mpi.h"
#include "ryan.h"

typedef unsigned int (*char_counters)
	[CHARSET_SIZE + 1][CHARSET_SIZE + 1][CHARSET_SIZE];

typedef int64 (*crack_counters)
	[CHARSET_LENGTH][CHARSET_LENGTH][CHARSET_SIZE];

static CRC32_t checksum;

static void charset_filter_plaintexts(struct db_main *db)
{
	struct list_entry *current, *last;
	unsigned char *ptr;
	char key[PLAINTEXT_BUFFER_SIZE];

	last = NULL;
	if ((current = db->plaintexts->head))
	do {
		if (!current->data[0]) {
			list_del_next(db->plaintexts, last);
			continue;
		}

		for (ptr = (unsigned char *)current->data; *ptr; ptr++)
		if (*ptr < CHARSET_MIN || *ptr > CHARSET_MAX) {
			list_del_next(db->plaintexts, last);
			break;
		}
		if (*ptr) continue;

		strnzcpy(key, current->data, PLAINTEXT_BUFFER_SIZE);
		if (ext_filter(key)) {
			if (strlen(key) <= strlen(current->data))
				strcpy(current->data, key);
		} else {
			list_del_next(db->plaintexts, last);
			continue;
		}

		last = current;
	} while ((current = current->next));
}

static int cfputc(int c, FILE *stream)
{
	unsigned char ch;

	ch = c;
	CRC32_Update(&checksum, &ch, 1);

	return fputc(c, stream);
}

static void charset_checksum_header(struct charset_header *header)
{
	CRC32_Update(&checksum, header->version, sizeof(header->version));
	CRC32_Update(&checksum, &header->min, 1);
	CRC32_Update(&checksum, &header->max, 1);
	CRC32_Update(&checksum, &header->length, 1);
	CRC32_Update(&checksum, &header->count, 1);
	CRC32_Update(&checksum, header->offsets, sizeof(header->offsets));
	CRC32_Update(&checksum, header->order, sizeof(header->order));
	CRC32_Final(header->check, checksum);
}

static void charset_write_header(FILE *file, struct charset_header *header)
{
	fwrite(header->version, sizeof(header->version), 1, file);
	fwrite(header->check, sizeof(header->check), 1, file);
	fputc(header->min, file);
	fputc(header->max, file);
	fputc(header->length, file);
	fputc(header->count, file);
	fwrite(header->offsets, sizeof(header->offsets), 1, file);
	fwrite(header->order, sizeof(header->order), 1, file);
}

void charset_read_header(FILE *file, struct charset_header *header)
{
	fread(header->version, sizeof(header->version), 1, file);
	if (memcmp(header->version, CHARSET_V1, sizeof(header->version)))
		fread(header->check, sizeof(header->check), 1, file);
	else
		memset(header->check, 0, sizeof(header->check));
	header->min = getc(file);
	header->max = getc(file);
	header->length = getc(file);
	header->count = getc(file);
	fread(header->offsets, sizeof(header->offsets), 1, file);
	fread(header->order, sizeof(header->order), 1, file);
}

static int charset_new_length(int length,
	struct charset_header *header, FILE *file)
{
	int result;
	long offset;

	if ((result = length < CHARSET_LENGTH)) {
		printf("%d ", length + 1);
		fflush(stdout);

		if ((offset = ftell(file)) < 0) pexit("ftell");
		header->offsets[length][0] = offset;
		header->offsets[length][1] = offset >> 8;
		header->offsets[length][2] = offset >> 16;
		header->offsets[length][3] = offset >> 24;
	}

	return result;
}

static void charset_generate_chars(struct list_entry *plaintexts,
	FILE *file, struct charset_header *header,
	char_counters chars, crack_counters cracks)
{
	struct list_entry *current;
	unsigned char *ptr;
	unsigned char buffer[CHARSET_SIZE];
	int length, pos, best, count;
	unsigned int value, max;
	int i, j, k;

	current = plaintexts;
	do {
		for (ptr = (unsigned char *)current->data; *ptr; ptr++)
			(*chars)[0][0][ARCH_INDEX(*ptr - CHARSET_MIN)]++;
	} while ((current = current->next));

	count = 0;
	best = 0;
	do {
		max = 0;
		for (k = 0; k < CHARSET_SIZE; k++)
		if ((value = (*chars)[0][0][k]) > max) {
			max = value; best = k;
		}
		if (!max) break;

		(*chars)[0][0][best] = 0;
		buffer[count++] = CHARSET_MIN + best;
	} while (1);

	header->count = count;
	fwrite(buffer, 1, count, file);
	CRC32_Update(&checksum, buffer, count);

	for (length = 0; charset_new_length(length, header, file); length++)
	for (pos = 0; pos <= length; pos++) {
		if (event_abort) return;

		cfputc(CHARSET_ESC, file); cfputc(CHARSET_NEW, file);
		cfputc(length, file); cfputc(pos, file);

		memset(chars, 0, sizeof(*chars));

		current = plaintexts;
		do
		if ((int)strlen(current->data) == length + 1) {
			ptr = (unsigned char *)current->data;
			(*chars)
				[CHARSET_SIZE]
				[CHARSET_SIZE]
				[ARCH_INDEX(ptr[pos] - CHARSET_MIN)]++;
			if (pos) (*chars)
				[CHARSET_SIZE]
				[ARCH_INDEX(ptr[pos - 1] - CHARSET_MIN)]
				[ARCH_INDEX(ptr[pos] - CHARSET_MIN)]++;
			if (pos > 1) (*chars)
				[ARCH_INDEX(ptr[pos - 2] - CHARSET_MIN)]
				[ARCH_INDEX(ptr[pos - 1] - CHARSET_MIN)]
				[ARCH_INDEX(ptr[pos] - CHARSET_MIN)]++;
		} while ((current = current->next));

		for (i = (pos > 1 ? 0 : CHARSET_SIZE); i <= CHARSET_SIZE; i++)
		for (j = (pos ? 0 : CHARSET_SIZE); j <= CHARSET_SIZE; j++) {
			count = 0;
			do {
				max = 0;
				for (k = 0; k < CHARSET_SIZE; k++)
				if ((value = (*chars)[i][j][k]) > max) {
					max = value; best = k;
				}

				if (i == CHARSET_SIZE && j == CHARSET_SIZE)
					(*cracks)[length][pos][count].lo = max;

				if (!max) break;

				(*chars)[i][j][best] = 0;
				buffer[count++] = CHARSET_MIN + best;
			} while (1);

			if (count) {
				cfputc(CHARSET_ESC, file);
				cfputc(CHARSET_LINE, file);
				cfputc(i, file); cfputc(j, file);
				fwrite(buffer, 1, count, file);
				CRC32_Update(&checksum, buffer, count);
			}
		}
	}

	cfputc(CHARSET_ESC, file); cfputc(CHARSET_NEW, file);
	cfputc(CHARSET_LENGTH, file);
}

static void charset_generate_order(crack_counters cracks, unsigned char *order)
{
	int length, pos, count;
	int best_length, best_pos, best_count;
	unsigned int div;
	int64 total, tmp, min, *value;
	unsigned char *ptr;

	for (length = 0; length < CHARSET_LENGTH; length++)
	for (count = 0; count < CHARSET_SIZE; count++) {
		pow64of32(&total, count + 1, length + 1);
		pow64of32(&tmp, count, length + 1);
		neg64(&tmp);
		add64to64(&total, &tmp);
		mul64by32(&total, CHARSET_SCALE);
		if (count) div64by32(&total, length + 1);

		for (pos = 0; pos <= length; pos++) {
			tmp = total;
			if ((div = (*cracks)[length][pos][count].lo))
				div64by32(&tmp, div);
			(*cracks)[length][pos][count] = tmp;
		}
	}

	ptr = order;
	best_length = best_pos = best_count = 0;
	do {
		min.hi = min.lo = 0xFFFFFFFF;

		for (length = 0; length < CHARSET_LENGTH; length++)
		for (count = 0; count < CHARSET_SIZE; count++)
		for (pos = 0; pos <= length; pos++) {
			value = &(*cracks)[length][pos][count];
			if (value->hi < min.hi ||
			    (value->hi == min.hi && value->lo < min.lo)) {
				min = *value;
				best_length = length;
				best_pos = pos;
				best_count = count;
			}
		}

		if (min.hi >= 0xFFFFFFFF && min.lo >= 0xFFFFFFFF) break;

		value = &(*cracks)[best_length][best_pos][best_count];
		value->hi = value->lo = 0xFFFFFFFF;
		*ptr++ = best_length;
		*ptr++ = best_pos;
		*ptr++ = best_count;
	} while (!event_abort);
}

static void charset_generate_all(struct list_entry *plaintexts, char *charset)
{
	FILE *file;
	int error;
	struct charset_header *header;
	char_counters chars;
	crack_counters cracks;

/* deprecated */
/*	strcat(charset, ".");		*/
/* 	strcat(charset, id2string());	*/

	header = (struct charset_header *)mem_alloc(sizeof(*header));
	memset(header, 0, sizeof(*header));

	chars = (char_counters)mem_alloc(sizeof(*chars));
	memset(chars, 0, sizeof(*chars));

	cracks = (crack_counters)mem_alloc(sizeof(*cracks));

	if (!(file = fopen(path_expand(charset), "wb")))
		pexit("fopen: %s", path_expand(charset));

	charset_write_header(file, header);

	printf("Generating charsets... ");
	fflush(stdout);

	charset_generate_chars(plaintexts, file, header, chars, cracks);
	if (event_abort) {
		fclose(file);
		unlink(charset);
		putchar('\n'); check_abort(0);
	}

	printf("DONE\nGenerating cracking order... ");
	fflush(stdout);

	charset_generate_order(cracks, header->order);
	if (event_abort) {
		fclose(file);
		unlink(charset);
		putchar('\n'); check_abort(0);
	}

	puts("DONE");

	fflush(file);
	if (!ferror(file) && !fseek(file, 0, SEEK_SET)) {
		strcpy(header->version, CHARSET_V);
		header->min = CHARSET_MIN;
		header->max = CHARSET_MAX;
		header->length = CHARSET_LENGTH;
		charset_checksum_header(header);
		charset_write_header(file, header);
	}

	MEM_FREE(cracks);
	MEM_FREE(chars);

	error = ferror(file);
	if (error | fclose(file)) {
		unlink(charset);
		pexit("%s", charset);
	}

	printf("Successfully written charset file: %s (%d character%s)\n",
		charset, header->count, header->count != 1 ? "s" : "");

	MEM_FREE(header);
}

static char *charset_self_test(void)
{
	int64 total, tmp, check;
	int n;

	pow64of32(&total, CHARSET_SIZE, CHARSET_LENGTH);
	check = total;
	n = CHARSET_LENGTH;
	while (--n > 0)
		div64by32(&check, CHARSET_SIZE);
	if (check.hi != 0 || check.lo != CHARSET_SIZE)
		return "pow64of32() overflow";

	pow64of32(&tmp, CHARSET_SIZE - 1, CHARSET_LENGTH);
	neg64(&tmp);
	add64to64(&total, &tmp);
	check = total;
	mul64by32(&check, CHARSET_SCALE);
	div64by32(&check, CHARSET_SCALE);
	if (check.hi != total.hi || check.lo != total.lo)
		return "mul64by32() overflow";

	return NULL;
}

void do_makechars(struct db_main *db, char *charset)
{
	char *where;

	if ((where = charset_self_test())) {
		fprintf(stderr, "Self test failed (%s)\n", where);
		error();
	}

	charset_filter_plaintexts(db);

	printf("Loaded %d plaintext%s%s\n",
		db->plaintexts->count,
		db->plaintexts->count != 1 ? "s" : "",
		db->plaintexts->count ? "" : ", exiting...");

	if (!db->plaintexts->count) return;

	CRC32_Init(&checksum);

	charset_generate_all(db->plaintexts->head, charset);
}
