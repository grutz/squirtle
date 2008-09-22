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

# Squirtle's Postgres Object

class DB
	
	# make a connection to the database
	def connect(options)
		
		puts "[*] Connecting to Postgres database"
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

	def create(options)
		puts "[*] Creating database: #{dbname} and tables . . ."
		
	end
	
end
