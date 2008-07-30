#! /usr/bin/python

# This file is Copyright 2005 Mario Zoppetti, and was added by
# Darryl A. Dixon <esrever_otua@pythonhacker.is-a-geek.net> to 
# 'NTLM Authorization Proxy Server',
# Copyright 2001 Dmitry A. Rozmanov <dima@xenon.spb.ru>
#
# NTLM APS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# NTLM APS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with the sofware; see the file COPYING. If not, write to the
# Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
#
# setup.py
from distutils.core import setup
import py2exe
import sys
import re
sys.argv.append("py2exe")

# Hmmmmmm.
repline = re.compile("(?P<before>^conf.*?)__init__.*?(?P<after>\)\)$)", re.M|re.S)
fileh = open('main.py', 'r')
code = fileh.read()
fileh.close()
newcode = re.sub(repline, re.search(repline, code).group('before')+"'./'"+re.search(repline, code).group('after'), code)
fileh = open('main.py', 'w')
fileh.write(newcode)
fileh.close()

setup(name='ntlmaps',
    version='0.9.9.5',
    console=["main.py"],
    package_dir = {'': 'lib'},
    options = {"py2exe": {"packages": ["encodings"]}},
    py_modules = ['basic_auth',
        'config',
        'config_affairs',
        'des',
        'des_c',
        'des_data',
        'http_header',
        'logger',
        'md4',
        'monitor_upstream',
        'ntlm_auth',
        'ntlm_messages',
        'ntlm_procs',
        'proxy_client',
        'server',
        'U32',
        'utils'],
    data_files=[("",["server.cfg"]),],
    description='NTLM local Proxy',
    author='Dmitry A. Rozmanov',
    author_email='<dima@xenon.spb.ru',
    url='http://ntlmaps.sourceforge.net/',
    )
