#! /usr/bin/env python

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
import __init__

import sys
from optparse import OptionParser

import server, config, config_affairs

parser = OptionParser()
parser.add_option("-k", "--key", type="string",
                  dest="key", default='',
                  action="store", help="Squirtle User Key to emulate")

parser.add_option("-c", "--config", type="string",
                dest="conffile", default='server.cfg',
                action="store", help="ntlmaps configuration file")
                
parser.add_option("-u", "--user", type="string",
                dest="user", default='',
                action="store", help="Username for pass the hash")

parser.add_option("-p", "--passhash", type="string",
                dest="passhash", default='',
                action="store", help="LM:NT hashes for pass the hash")

(options, args) = parser.parse_args()

if options.conffile == '':
    conffile = config.findConfigFileNameInArgv(sys.argv, __init__.ntlmaps_dir+'/')

#--------------------------------------------------------------
# config affairs
# look for default config name in lib/config.py
#conf = config.read_config(config.findConfigFileNameInArgv(sys.argv, __init__.ntlmaps_dir+'/'))

conf = config.read_config(options.conffile)

conf['GENERAL']['VERSION'] = '0.9.9.5-squirtle-1'
conf['SQUIRTLE']['KEY'] = options.key
conf['NTLM_AUTH']['USER'] = options.user
conf['NTLM_AUTH']['PASSWORD'] = options.passhash

#--------------------------------------------------------------
print 'NTLM authorization Proxy Server v%s' % conf['GENERAL']['VERSION']
print 'Copyright (C) 2001-2004 by Dmitry Rozmanov and others.'
print 'Squirtle Modifications (c) 2008 by Kurt Grutzmacher'
 
config = config_affairs.arrange(conf)


#--------------------------------------------------------------
# let's run it
serv = server.AuthProxyServer(config)
serv.run()
