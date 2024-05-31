#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) Google LLC, 2020
#
# Author: Nathan Huckleberry <nhuck@google.com>
#
"""A helper routine run clang-tidy and the clang static-analyzer on
compile_commands.json.
"""

import argparse
import json
import multiprocessing
import subprocess
import sys


def parse_arguments():
    """Set up and parses command-line arguments.
    Returns:
        args: Dict of parsed args
        Has keys: [path, type]
    """
    usage = """Run clang-tidy or the clang static-analyzer on a
        compilation database."""
    parser = argparse.ArgumentParser(description=usage)

    type_help = "Type of analysis to be performed"
    parser.add_argument("type",
                        choices=["clang-tidy", "clang-analyzer"],
                        help=type_help)
    path_help = "Path to the compilation database to parse"
    parser.add_argument("path", type=str, help=path_help)

    checks_help = "Checks to pass to the analysis"
    parser.add_argument("-checks", type=str, default=None, help=checks_help)
    header_filter_help = "Pass the -header-filter value to the tool"
    parser.add_argument("-header-filter", type=str, default=None, help=header_filter_help)

    return parser.parse_args()


def init(l, a):
    global lock
    global args
    lock = l
    args = a


def run_analysis(entry):
    # Disable all checks, then re-enable the ones we want
    global args
    checks = None
    if args.checks:
        checks = args.checks.split(',')
    else:
        checks = ["-*"]
        if args.type == "clang-tidy":
            checks.append("linuxkernel-*")
        else:
            checks.append("clang-analyzer-*")
            checks.append("-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling")
    file = entry["file"]
    if not file.endswith(".c") and not file.endswith(".cpp"):
        with lock:
            print(f"Skipping non-C file: '{file}'", file=sys.stderr)
        return
    pargs = ["clang-tidy", "-p", args.path, "-checks=" + ",".join(checks)]
    if args.header_filter:
        pargs.append("-header-filter=" + args.header_filter)
    pargs.append(file)
    p = subprocess.run(pargs,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT,
                       cwd=entry["directory"])
    with lock:
        sys.stderr.buffer.write(p.stdout)


def main():
    try:
        args = parse_arguments()

        lock = multiprocessing.Lock()
        pool = multiprocessing.Pool(initializer=init, initargs=(lock, args))
        # Read JSON data into the datastore variable
        with open(args.path, "r") as f:
            datastore = json.load(f)
            pool.map(run_analysis, datastore)
    except BrokenPipeError:
        # Python flushes standard streams on exit; redirect remaining output
        # to devnull to avoid another BrokenPipeError at shutdown
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)  # Python exits with error code 1 on EPIPE


if __name__ == "__main__":
    main()
