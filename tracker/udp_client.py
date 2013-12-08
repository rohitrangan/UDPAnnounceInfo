import socket
import sys
import random
import struct

def get_transaction_id():
    return int(random.randrange(0, 255))

HOST, PORT = "localhost", 9999
# TEMPORARY CODE!!!
connection_id = 0x41727101980
action = 0x0
transaction_id = get_transaction_id()
buf = struct.pack("!q", connection_id)
buf += struct.pack("!i", action)
buf += struct.pack("!i", transaction_id)

print "Connection ID sent  = ", connection_id
print "Action sent         = ", action
print "Transaction ID sent = ", transaction_id

#data = " ".join(sys.argv[1:])

# SOCK_DGRAM is the socket type to use for UDP sockets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(8)

# As you can see, there is no connect() call; UDP has no connections.
# Instead, data is directly sent to the recipient via sendto().
sock.sendto(buf, (HOST, PORT))
received = sock.recv(2048)

if len(received) < 16:
    raise RuntimeError("Wrong response length getting connection id: %s" %
                        len(buf))
action = struct.unpack_from("!i", received)[0]
res_transaction_id = struct.unpack_from("!i", received, 4)[0]

if res_transaction_id != transaction_id:
    raise RuntimeError("Transaction ID does not match in connection"
                       " response! Expected %s, got %s"
                       % (sent_transaction_id, res_transaction_id))

if action == 0x0:
    connection_id = struct.unpack_from("!q", received, 8)[0]
    print "Received action         = ", action
    print "Received connection ID  = ", connection_id
    print "Received transaction ID = ", transaction_id
elif action == 0x3:                
    error = struct.unpack_from("!s", received, 8)
    raise RuntimeError("Error while trying to get a connection response: %s"
                        % error)

print "Sent:     {}".format(buf)
print "Received: {}".format(received)
