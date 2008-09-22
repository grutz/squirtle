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

# Squirtle's SQLite Object

require 'sqlite3'

class DB
	
	# make a connection to the database
	def connect(options)
		if not File.exists?(options[:database])
			create(options[:database])
		end
		
		begin
			ActiveRecord::Base.establish_connection(options)
		rescue ::Exception => e
			puts "[!] Error establishing database connection: #{e.to_s}"
			return False
		end
	end
	
	# remove a connection to the database
	def disconnect
		begin
			ActiveRecord::Base.remove_connection
		rescue ::Exception => e
			puts "[!] Error removing database connection: #{e.to_s}"
		end
	end

	def create(dbname)
		puts "[*] Creating database: #{dbname}"
		db = SQLite3::Database.new(dbname)

		puts "[*] Creating users table . . ."
		db.execute %q{
				CREATE TABLE users (
					id integer primary key,
					key varchar(32),
					timestamp varchar(30),
					ip varchar(16),
					browser varchar(255),
					user varchar(255),
					workstation varchar(255),
					domain varchar(255),
					nonce varchar(16),
					lm varchar(48),
					nt varchar(48)
				)
		}		

		# "func" can be one of:
		#   'static' => request client auth with static "nonce"
		#   'type2'  => request client auth to "type2" message
		#   'redir'  => force client to redirect to "url" and give up control

		puts "[*] Creating sessions table . . ."
		db.execute %q{
				CREATE TABLE sessions (
					id integer primary key,
					key_id varchar(32),
					timestamp varchar(30),
					function varchar(6),
					url varchar(255),
					nonce varchar(255),
					type2_base64 varchar(255),
					domain varchar(255),
					server varchar(255),
					dns_name varchar(255),
					dns_domain varchar(255),
					result varchar(255)
				)
		}
		db.close
	end
	
end
