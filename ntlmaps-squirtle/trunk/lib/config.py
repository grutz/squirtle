# This file is part of 'NTLM Authorization Proxy Server'
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

import string, getopt, os, sys

#-------------------------------------------------------------------------------------------
def read_config(fname):
    res = {}

    buf = open(fname).readlines()
    for line in buf:
        workingLine = string.strip(line)
        if workingLine:
            if workingLine[0] != '#':
                if workingLine[0] == '[' and workingLine[-1] == ']':
                    section_name = string.strip(workingLine[1:-1])
                    if section_name:
                        res[section_name] = {}
                else:
                    parts = string.split(workingLine, ':')
                    if len(parts) > 1:
		        res[section_name][string.strip(parts[0])] = string.lstrip(workingLine[string.find(workingLine, ':')+1:])
                        #res[section_name][string.strip(parts[0])] = parts
    return res

#-------------------------------------------------------------------------------------------
# Thanks Janek Schwarz <j.schwarz@i-change.de> for this addition.

def findConfigFileNameInArgv(argv, configFileDir=''):
    """ Resolves configuration file. Resolution goes as follows:
    if the command switch '-c' is given its argument is taken as
    the config file. Otherwise the function falls back to
    'server.cfg' in the current directory. """

    configFileName = configFileDir+'server.cfg'

    optionsList, notUsedArguments = getopt.getopt(argv[1:], 'c:')

    for i in optionsList:
        option, value = i
        if option == '-c' and value != '':
            try:
                handle = open(value)
                handle.close()
                configFileName = value
                break
            except IOError:
                print "ERROR: Config file specified with '-c' either does not exist or is not readable."
                sys.exit(1)

    return configFileName
