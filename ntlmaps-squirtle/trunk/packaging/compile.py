#!/usr/bin/python

"""
compile.py
Copyright (C) 2004 Darryl Dixon <esrever_otua@pythonhacker.is-a-geek.net>
This program may be freely redistributed under the terms of the GNU GPL
"""

from compileall import compile_dir
import sys

compile_dir(sys.argv[1])
