/*
 *	docproc is a simple preprocessor for the template files
 *      used as placeholders for the kernel internal documentation.
 *	docproc is used for documentation-frontend and
 *      dependency-generator.
 *	The two usages have in common that they require
 *	some knowledge of the .tmpl syntax, therefore they
 *	are kept together.
 *
 *	documentation-frontend
 *		Scans the template file and call kernel-doc for
 *		all occurrences of ![EIF]file
 *		Beforehand each referenced file is scanned for
 *		any symbols that are exported via these macros:
 *			EXPORT_SYMBOL(), EXPORT_SYMBOL_GPL(), &
 *			EXPORT_SYMBOL_GPL_FUTURE()
 *		This is used to create proper -function and
 *		-nofunction arguments in calls to kernel-doc.
 *		Usage: docproc doc file.tmpl
 *
 *	dependency-generator:
 *		Scans the template file and list all files
 *		referenced in a format recognized by make.
 *		Usage:	docproc depend file.tmpl
 *		Writes dependency information to stdout
 *		in the following format:
 *		file.tmpl src.c	src2.c
 *		The filenames are obtained from the following constructs:
 *		!Efilename
 *		!Ifilename
 *		!Dfilename
 *		!Ffilename
 *		!Pfilename
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

/* exitstatus is used to keep track of any failing calls to kernel-doc,
 * but execution continues. */
int exitstatus = 0;

typedef void DFL(char *);
DFL *defaultline;

typedef void FILEONLY(char * file);
FILEONLY *internalfunctions;
FILEONLY *externalfunctions;
FILEONLY *symbolsonly;
FILEONLY *findall;

typedef void FILELINE(char * file, char * line);
FILELINE * singlefunctions;
FILELINE * entity_system;
FILELINE * docsection;

#define MAXLINESZ     2048
#define MAXFILES      250
#define KERNELDOCPATH "scripts/"
#define KERNELDOC     "kernel-doc"
#define DOCBOOK       "-docbook"
#define RST           "-rst"
#define LIST          "-list"
#define FUNCTION      "-function"
#define NOFUNCTION    "-nofunction"
#define NODOCSECTIONS "-no-doc-sections"
#define SHOWNOTFOUND  "-show-not-found"

enum file_format {
	FORMAT_AUTO,
	FORMAT_DOCBOOK,
	FORMAT_RST,
};

static enum file_format file_format = FORMAT_AUTO;

#define KERNELDOC_FORMAT	(file_format == FORMAT_RST ? RST : DOCBOOK)

static char *srctree, *kernsrctree;

static char **all_list = NULL;
static int all_list_len = 0;

static void consume_symbol(const char *sym)
{
	int i;

	for (i = 0; i < all_list_len; i++) {
		if (!all_list[i])
			continue;
		if (strcmp(sym, all_list[i]))
			continue;
		all_list[i] = NULL;
		break;
	}
}

static void usage (void)
{
	fprintf(stderr, "Usage: docproc [{--docbook|--rst}] {doc|depend} file\n");
	fprintf(stderr, "Input is read from file.tmpl. Output is sent to stdout\n");
	fprintf(stderr, "doc: frontend when generating kernel documentation\n");
	fprintf(stderr, "depend: generate list of files referenced within file\n");
	fprintf(stderr, "Environment variable SRCTREE: absolute path to sources.\n");
	fprintf(stderr, "                     KBUILD_SRC: absolute path to kernel source tree.\n");
}

/*
 * Execute kernel-doc with parameters given in svec
 */
static void exec_kernel_doc(char **svec)
{
	pid_t pid;
	int ret;
	char real_filename[PATH_MAX + 1];
	/* Make sure output generated so far are flushed */
	fflush(stdout);
	switch (pid=fork()) {
		case -1:
			perror("fork");
			exit(1);
		case  0:
			memset(real_filename, 0, sizeof(real_filename));
			strncat(real_filename, kernsrctree, PATH_MAX);
			strncat(real_filename, "/" KERNELDOCPATH KERNELDOC,
					PATH_MAX - strlen(real_filename));
			execvp(real_filename, svec);
			fprintf(stderr, "exec ");
			perror(real_filename);
			exit(1);
		default:
			waitpid(pid, &ret ,0);
	}
	if (WIFEXITED(ret))
		exitstatus |= WEXITSTATUS(ret);
	else
		exitstatus = 0xff;
}

/* Types used to create list of all exported symbols in a number of files */
struct symbols
{
	char *name;
};

struct symfile
{
	char *filename;
	struct symbols *symbollist;
	int symbolcnt;
};

struct symfile symfilelist[MAXFILES];
int symfilecnt = 0;

static void add_new_symbol(struct symfile *sym, char * symname)
{
	sym->symbollist =
	  realloc(sym->symbollist, (sym->symbolcnt + 1) * sizeof(char *));
	sym->symbollist[sym->symbolcnt++].name = strdup(symname);
}

/* Add a filename to the list */
static struct symfile * add_new_file(char * filename)
{
	symfilelist[symfilecnt++].filename = strdup(filename);
	return &symfilelist[symfilecnt - 1];
}

/* Check if file already are present in the list */
static struct symfile * filename_exist(char * filename)
{
	int i;
	for (i=0; i < symfilecnt; i++)
		if (strcmp(symfilelist[i].filename, filename) == 0)
			return &symfilelist[i];
	return NULL;
}

/*
 * List all files referenced within the template file.
 * Files are separated by tabs.
 */
static void adddep(char * file)		   { printf("\t%s", file); }
static void adddep2(char * file, char * line)     { line = line; adddep(file); }
static void noaction(char * line)		   { line = line; }
static void noaction2(char * file, char * line)   { file = file; line = line; }

/* Echo the line without further action */
static void printline(char * line)               { printf("%s", line); }

/*
 * Find all symbols in filename that are exported with EXPORT_SYMBOL &
 * EXPORT_SYMBOL_GPL (& EXPORT_SYMBOL_GPL_FUTURE implicitly).
 * All symbols located are stored in symfilelist.
 */
static void find_export_symbols(char * filename)
{
	FILE * fp;
	struct symfile *sym;
	char line[MAXLINESZ];
	if (filename_exist(filename) == NULL) {
		char real_filename[PATH_MAX + 1];
		memset(real_filename, 0, sizeof(real_filename));
		strncat(real_filename, srctree, PATH_MAX);
		strncat(real_filename, "/", PATH_MAX - strlen(real_filename));
		strncat(real_filename, filename,
				PATH_MAX - strlen(real_filename));
		sym = add_new_file(filename);
		fp = fopen(real_filename, "r");
		if (fp == NULL)	{
			fprintf(stderr, "docproc: ");
			perror(real_filename);
			exit(1);
		}
		while (fgets(line, MAXLINESZ, fp)) {
			char *p;
			char *e;
			if (((p = strstr(line, "EXPORT_SYMBOL_GPL")) != NULL) ||
			    ((p = strstr(line, "EXPORT_SYMBOL")) != NULL)) {
				/* Skip EXPORT_SYMBOL{_GPL} */
				while (isalnum(*p) || *p == '_')
					p++;
				/* Remove parentheses & additional whitespace */
				while (isspace(*p))
					p++;
				if (*p != '(')
					continue; /* Syntax error? */
				else
					p++;
				while (isspace(*p))
					p++;
				e = p;
				while (isalnum(*e) || *e == '_')
					e++;
				*e = '\0';
				add_new_symbol(sym, p);
			}
		}
		fclose(fp);
	}
}

/*
 * Document all external or internal functions in a file.
 * Call kernel-doc with following parameters:
 * kernel-doc [-docbook|-rst] -nofunction function_name1 filename
 * Function names are obtained from all the src files
 * by find_export_symbols.
 * intfunc uses -nofunction
 * extfunc uses -function
 */
static void docfunctions(char * filename, char * type)
{
	int i,j;
	int symcnt = 0;
	int idx = 0;
	char **vec;

	for (i=0; i <= symfilecnt; i++)
		symcnt += symfilelist[i].symbolcnt;
	vec = malloc((2 + 2 * symcnt + 3) * sizeof(char *));
	if (vec == NULL) {
		perror("docproc: ");
		exit(1);
	}
	vec[idx++] = KERNELDOC;
	vec[idx++] = KERNELDOC_FORMAT;
	vec[idx++] = NODOCSECTIONS;
	for (i=0; i < symfilecnt; i++) {
		struct symfile * sym = &symfilelist[i];
		for (j=0; j < sym->symbolcnt; j++) {
			vec[idx++]     = type;
			consume_symbol(sym->symbollist[j].name);
			vec[idx++] = sym->symbollist[j].name;
		}
	}
	vec[idx++]     = filename;
	vec[idx] = NULL;
	if (file_format == FORMAT_RST)
		printf(".. %s\n", filename);
	else
		printf("<!-- %s -->\n", filename);
	exec_kernel_doc(vec);
	fflush(stdout);
	free(vec);
}
static void intfunc(char * filename) {	docfunctions(filename, NOFUNCTION); }
static void extfunc(char * filename) { docfunctions(filename, FUNCTION);   }

/*
 * Document specific function(s) in a file.
 * Call kernel-doc with the following parameters:
 * kernel-doc -docbook -function function1 [-function function2]
 */
static void singfunc(char * filename, char * line)
{
	char *vec[200]; /* Enough for specific functions */
	int i, idx = 0;
	int startofsym = 1;
	vec[idx++] = KERNELDOC;
	vec[idx++] = KERNELDOC_FORMAT;
	vec[idx++] = SHOWNOTFOUND;

	/* Split line up in individual parameters preceded by FUNCTION */
	for (i=0; line[i]; i++) {
		if (isspace(line[i])) {
			line[i] = '\0';
			startofsym = 1;
			continue;
		}
		if (startofsym) {
			startofsym = 0;
			vec[idx++] = FUNCTION;
			vec[idx++] = &line[i];
		}
	}
	for (i = 0; i < idx; i++) {
		if (strcmp(vec[i], FUNCTION))
			continue;
		consume_symbol(vec[i + 1]);
	}
	vec[idx++] = filename;
	vec[idx] = NULL;
	exec_kernel_doc(vec);
}

/*
 * Insert specific documentation section from a file.
 * Call kernel-doc with the following parameters:
 * kernel-doc -docbook -function "doc section" filename
 */
static void docsect(char *filename, char *line)
{
	/* kerneldoc -docbook -show-not-found -function "section" file NULL */
	char *vec[7];
	char *s;

	for (s = line; *s; s++)
		if (*s == '\n')
			*s = '\0';

	if (asprintf(&s, "DOC: %s", line) < 0) {
		perror("asprintf");
		exit(1);
	}
	consume_symbol(s);
	free(s);

	vec[0] = KERNELDOC;
	vec[1] = KERNELDOC_FORMAT;
	vec[2] = SHOWNOTFOUND;
	vec[3] = FUNCTION;
	vec[4] = line;
	vec[5] = filename;
	vec[6] = NULL;
	exec_kernel_doc(vec);
}

static void find_all_symbols(char *filename)
{
	char *vec[4]; /* kerneldoc -list file NULL */
	pid_t pid;
	int ret, i, count, start;
	char real_filename[PATH_MAX + 1];
	int pipefd[2];
	char *data, *str;
	size_t data_len = 0;

	vec[0] = KERNELDOC;
	vec[1] = LIST;
	vec[2] = filename;
	vec[3] = NULL;

	if (pipe(pipefd)) {
		perror("pipe");
		exit(1);
	}

	switch (pid=fork()) {
		case -1:
			perror("fork");
			exit(1);
		case  0:
			close(pipefd[0]);
			dup2(pipefd[1], 1);
			memset(real_filename, 0, sizeof(real_filename));
			strncat(real_filename, kernsrctree, PATH_MAX);
			strncat(real_filename, "/" KERNELDOCPATH KERNELDOC,
					PATH_MAX - strlen(real_filename));
			execvp(real_filename, vec);
			fprintf(stderr, "exec ");
			perror(real_filename);
			exit(1);
		default:
			close(pipefd[1]);
			data = malloc(4096);
			do {
				while ((ret = read(pipefd[0],
						   data + data_len,
						   4096)) > 0) {
					data_len += ret;
					data = realloc(data, data_len + 4096);
				}
			} while (ret == -EAGAIN);
			if (ret != 0) {
				perror("read");
				exit(1);
			}
			waitpid(pid, &ret ,0);
	}
	if (WIFEXITED(ret))
		exitstatus |= WEXITSTATUS(ret);
	else
		exitstatus = 0xff;

	count = 0;
	/* poor man's strtok, but with counting */
	for (i = 0; i < data_len; i++) {
		if (data[i] == '\n') {
			count++;
			data[i] = '\0';
		}
	}
	start = all_list_len;
	all_list_len += count;
	all_list = realloc(all_list, sizeof(char *) * all_list_len);
	str = data;
	for (i = 0; i < data_len && start != all_list_len; i++) {
		if (data[i] == '\0') {
			all_list[start] = str;
			str = data + i + 1;
			start++;
		}
	}
}

/*
 * Terminate s at first space, if any. If there was a space, return pointer to
 * the character after that. Otherwise, return pointer to the terminating NUL.
 */
static char *chomp(char *s)
{
	while (*s && !isspace(*s))
		s++;

	if (*s)
		*s++ = '\0';

	return s;
}

/* Return pointer to directive content, or NULL if not a directive. */
static char *is_directive(char *line)
{
	if (file_format == FORMAT_DOCBOOK && line[0] == '!')
		return line + 1;
	else if (file_format == FORMAT_RST && !strncmp(line, ".. !", 4))
		return line + 4;

	return NULL;
}

/*
 * Parse file, calling action specific functions for:
 * 1) Lines containing !E
 * 2) Lines containing !I
 * 3) Lines containing !D
 * 4) Lines containing !F
 * 5) Lines containing !P
 * 6) Lines containing !C
 * 7) Default lines - lines not matching the above
 */
static void parse_file(FILE *infile)
{
	char line[MAXLINESZ];
	char *p, *s;
	while (fgets(line, MAXLINESZ, infile)) {
		p = is_directive(line);
		if (!p) {
			defaultline(line);
			continue;
		}

		switch (*p++) {
		case 'E':
			chomp(p);
			externalfunctions(p);
			break;
		case 'I':
			chomp(p);
			internalfunctions(p);
			break;
		case 'D':
			chomp(p);
			symbolsonly(p);
			break;
		case 'F':
			/* filename */
			s = chomp(p);
			/* function names */
			while (isspace(*s))
				s++;
			singlefunctions(p, s);
			break;
		case 'P':
			/* filename */
			s = chomp(p);
			/* DOC: section name */
			while (isspace(*s))
				s++;
			docsection(p, s);
			break;
		case 'C':
			chomp(p);
			if (findall)
				findall(p);
			break;
		default:
			defaultline(line);
		}
	}
	fflush(stdout);
}

/*
 * Is this a RestructuredText template?  Answer the question by seeing if its
 * name ends in ".rst".
 */
static int is_rst(const char *file)
{
	char *dot = strrchr(file, '.');

	return dot && !strcmp(dot + 1, "rst");
}

enum opts {
	OPT_DOCBOOK,
	OPT_RST,
	OPT_HELP,
};

int main(int argc, char *argv[])
{
	const char *subcommand, *filename;
	FILE * infile;
	int i;

	srctree = getenv("SRCTREE");
	if (!srctree)
		srctree = getcwd(NULL, 0);
	kernsrctree = getenv("KBUILD_SRC");
	if (!kernsrctree || !*kernsrctree)
		kernsrctree = srctree;

	for (;;) {
		int c;
		struct option opts[] = {
			{ "docbook",	no_argument, NULL, OPT_DOCBOOK },
			{ "rst",	no_argument, NULL, OPT_RST },
			{ "help",	no_argument, NULL, OPT_HELP },
			{}
		};

		c = getopt_long_only(argc, argv, "", opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case OPT_DOCBOOK:
			file_format = FORMAT_DOCBOOK;
			break;
		case OPT_RST:
			file_format = FORMAT_RST;
			break;
		case OPT_HELP:
			usage();
			return 0;
		default:
		case '?':
			usage();
			return 1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage();
		exit(1);
	}

	subcommand = argv[0];
	filename = argv[1];

	if (file_format == FORMAT_AUTO)
		file_format = is_rst(filename) ? FORMAT_RST : FORMAT_DOCBOOK;

	/* Open file, exit on error */
	infile = fopen(filename, "r");
	if (infile == NULL) {
		fprintf(stderr, "docproc: ");
		perror(filename);
		exit(2);
	}

	if (strcmp("doc", subcommand) == 0) {
		if (file_format == FORMAT_RST) {
			time_t t = time(NULL);
			printf(".. generated from %s by docproc %s\n",
			       filename, ctime(&t));
		}

		/* Need to do this in two passes.
		 * First pass is used to collect all symbols exported
		 * in the various files;
		 * Second pass generate the documentation.
		 * This is required because some functions are declared
		 * and exported in different files :-((
		 */
		/* Collect symbols */
		defaultline       = noaction;
		internalfunctions = find_export_symbols;
		externalfunctions = find_export_symbols;
		symbolsonly       = find_export_symbols;
		singlefunctions   = noaction2;
		docsection        = noaction2;
		findall           = find_all_symbols;
		parse_file(infile);

		/* Rewind to start from beginning of file again */
		fseek(infile, 0, SEEK_SET);
		defaultline       = printline;
		internalfunctions = intfunc;
		externalfunctions = extfunc;
		symbolsonly       = printline;
		singlefunctions   = singfunc;
		docsection        = docsect;
		findall           = NULL;

		parse_file(infile);

		for (i = 0; i < all_list_len; i++) {
			if (!all_list[i])
				continue;
			fprintf(stderr, "Warning: didn't use docs for %s\n",
				all_list[i]);
		}
	} else if (strcmp("depend", subcommand) == 0) {
		/* Create first part of dependency chain
		 * file.tmpl */
		printf("%s\t", filename);
		defaultline       = noaction;
		internalfunctions = adddep;
		externalfunctions = adddep;
		symbolsonly       = adddep;
		singlefunctions   = adddep2;
		docsection        = adddep2;
		findall           = adddep;
		parse_file(infile);
		printf("\n");
	} else {
		fprintf(stderr, "Unknown option: %s\n", subcommand);
		exit(1);
	}
	fclose(infile);
	fflush(stdout);
	return exitstatus;
}
