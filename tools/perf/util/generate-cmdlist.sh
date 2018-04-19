#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

echo "/* Automatically generated by $0 */
struct cmdname_help
{
    char name[16];
    char help[80];
};

static struct cmdname_help common_cmds[] = {"

sed -n -e 's/^perf-\([^ 	]*\)[ 	].* common.*/\1/p' command-list.txt |
sort |
while read cmd
do
     sed -n '
     /^NAME/,/perf-'"$cmd"'/H
     ${
            x
            s/.*perf-'"$cmd"' - \(.*\)/  {"'"$cmd"'", "\1"},/
	    p
     }' "Documentation/perf-$cmd.txt"
done

echo "#ifdef HAVE_LIBELF_SUPPORT"
sed -n -e 's/^perf-\([^ 	]*\)[ 	].* full.*/\1/p' command-list.txt |
sort |
while read cmd
do
     sed -n '
     /^NAME/,/perf-'"$cmd"'/H
     ${
            x
            s/.*perf-'"$cmd"' - \(.*\)/  {"'"$cmd"'", "\1"},/
	    p
     }' "Documentation/perf-$cmd.txt"
done
echo "#endif /* HAVE_LIBELF_SUPPORT */"

echo "#ifdef HAVE_LIBAUDIT_SUPPORT"
sed -n -e 's/^perf-\([^ 	]*\)[ 	].* audit*/\1/p' command-list.txt |
sort |
while read cmd
do
     sed -n '
     /^NAME/,/perf-'"$cmd"'/H
     ${
            x
            s/.*perf-'"$cmd"' - \(.*\)/  {"'"$cmd"'", "\1"},/
	    p
     }' "Documentation/perf-$cmd.txt"
done
echo "#endif /* HAVE_LIBELF_SUPPORT */"
echo "};"
