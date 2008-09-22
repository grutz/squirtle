# Copyright (C) 2008  Kurt Grutzmacher
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Squirtle's Database Objects

require 'active_record'

class DB
	
	# parsing the db strong from the configuration file
	def setup(opts = '')
				
		case opts
		when /^sqlite:/ then do_sqlite(opts)
		when /^mysql:/ then do_mysql(opts)
		when /^postgres:/ then do_postgres(opts)
		end
	end
	
	# ah, sqlite you say? sure!
	def do_sqlite(opts)
		conn = {}
		conn[:adapter] = 'sqlite3'
		conn[:database] = opts.sub!("sqlite://", '')

		require 'sq_sqlite'
		$config['dbopts'] = conn
	end
	
	# mysql, my favorite!
	def do_mysql(opt)
		opt = opt.sub!("mysql://", '')

		conn = {}
		conn[:adapter] = 'mysql'
		
		auth, dest = opt.split('@')
		(dest = auth and auth = nil) if not dest
		conn[:username], conn[:password] = auth.split(':') if auth
		target, conn[:database] = dest.split('/')
		(conn[:database] = target and target = nil) if not conn[:database]
		conn[:host],port = target.split(':') if target
		if not port then
			conn[:port] = 3306
		else
			conn[:port] = port.to_i
		end
		
		require 'sq_mysql'
		$config['dbopts'] = conn
	end
	
	# postgress!  (untested)
	def do_postgres(opt)
			opt = opt.sub!("postgres://", '')

			conn = {}
			conn[:adapter] = 'postgres'

			auth, dest = opt.split('@')
			(dest = auth and auth = nil) if not dest
			conn[:username], conn[:password] = auth.split(':') if auth
			target, conn[:database] = dest.split('/')
			(conn[:database] = target and target = nil) if not conn[:database]
			conn[:host],port = target.split(':') if target
			if not port then
				conn[:port] = 3306
			else
				conn[:port] = port.to_i
			end

			require 'sq_postgres'
			$config['dbopts'] = conn
		end
	
end

class User < ActiveRecord::Base
	has_many :keys
end

class Session < ActiveRecord::Base
  belongs_to :users, :foreign_key => "key_id"
end
