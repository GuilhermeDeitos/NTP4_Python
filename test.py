from socket import AF_INET, SOCK_DGRAM
import sys
import socket
import struct, time

host = "pool.ntp.org"
port = 123
read_buffer = 1024
address = ( host, port )
data = '\x1b' + 47 * '\0'

epoch = 2208988800

client = socket.socket( AF_INET, SOCK_DGRAM )
client.sendto( data.encode(), address )

data, address = client.recvfrom( read_buffer )

t = struct.unpack( '!12I', data )[10]

t -= epoch

print( "Time = %s" % time.ctime( t ) )