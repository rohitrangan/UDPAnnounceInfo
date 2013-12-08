import socket
import sys
import random
import struct
import binascii

def udp_get_transaction_id():
    return int(random.randrange(0, 255))

def get_peer_id():
    # We follow Azures-style encoding for peer ID generation. Refer to
    # https://wiki.theory.org/index.php/BitTorrentSpecification#peer_id
    peer_id_ret = '-PY1000-'
    for i in range(0, 12):
        peer_id_ret += str(random.randrange(0, 9))
    return peer_id_ret

def get_announce_key():
    # Random 32-bit announce key.
    return int(random.randrange(0, 4294967295))

def udp_create_announce_request(connection_id, info_hash, port_num):
    # Refer to http://xbtt.sourceforge.net/udp_tracker_protocol.html
    action = 0x1
    transaction_id = udp_get_transaction_id()
    peer_id = get_peer_id()
    downloaded = 0x0
    left = 0xFF
    uploaded = 0x0
    event = 0x2
    ip = 0x0
    key = get_announce_key()
    num_want = -1
    port = port_num
    # buf contains the data we need to send the tracker.
    buf = struct.pack("!q", connection_id)
    buf += struct.pack("!i", action)
    buf += struct.pack("!i", transaction_id)
    buf += struct.pack("!20s", binascii.a2b_hex(info_hash))
    buf += struct.pack("!20s", peer_id)
    buf += struct.pack("!q", downloaded)
    buf += struct.pack("!q", left)
    buf += struct.pack("!q", uploaded)
    buf += struct.pack("!i", event)
    buf += struct.pack("!I", ip)
    buf += struct.pack("!I", key)
    buf += struct.pack("!i", num_want)
    buf += struct.pack("!H", port)
    return (buf, transaction_id)

def udp_parse_announce_response(buf, sent_transaction_id, info_hash):
    # buf contains all the data sent by the tracker.
    buf_size = len(buf)
    if buf_size < 20:
        raise RuntimeError("Wrong response length while scraping: %s" %
                           len(buf))        
    action = struct.unpack_from("!i", buf)[0]
    res_transaction_id = struct.unpack_from("!i", buf, 4)[0]

    if res_transaction_id != sent_transaction_id:
        raise RuntimeError("Transaction ID doesn't match in announce response"
                           "! Expected %s, got %s" % (sent_transaction_id,
                                                      res_transaction_id))
    if action == 0x1:
        ret = {}
        offset = 8;              
        interval = struct.unpack_from("!i", buf, offset)[0]
        offset += 4
        ret['interval'] = interval
        leechers = struct.unpack_from("!i", buf, offset)[0]
        offset += 4
        ret['peers'] = leechers
        seeders = struct.unpack_from("!i", buf, offset)[0]
        ret['seeds'] = seeders
        ret_seed_ips = []
        rest_amt = (buf_size - 20) / 6;
        
        # We have a variable number of peers, equal to rest_amt. We calculate
        # this using the information that every peer requires 6 bytes of data.
        # Refer to http://xbtt.sourceforge.net/udp_tracker_protocol.html for
        # more details.
        for i in range(0, rest_amt):
            offset += 4
            curr_ip_int = struct.unpack_from("!i", buf, offset)[0]
            curr_ip = socket.inet_ntoa(struct.pack('!i', curr_ip_int))
            offset += 2
            curr_ip_port = struct.unpack_from("!H", buf, offset)[0]
            ret_seed_ips.append(str(curr_ip) + ":" + str(curr_ip_port))

        ret['peer_list'] = ret_seed_ips
        return ret
    elif action == 0x3:
        # An error occured. We try to extract the error string.
        error = struct.unpack_from("!s", buf, 8)
        raise RuntimeError("Error while scraping: %s" % error)


HOST, PORT = "localhost", 9999
# TEMPORARY CODE!!!
connection_id = 0x41727101980
action = 0x0
transaction_id = udp_get_transaction_id()
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

# print "Announcing UDP: %s " % parsed_tracker.geturl()
#transaction_id = "\x00\x00\x04\x12\x27\x10\x19\x70";
#connection_id = "\x00\x00\x04\x17\x27\x10\x19\x80";
#sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#sock.settimeout(8)
#sock.connect((HOST, PORT))
#conn = (socket.gethostbyname(parsed_tracker.hostname), parsed_tracker.port)

info_hash = "4e503b4a2c6a5af61b1eb8aaf646f91dd0a1d080"

try:
    # Creating, sending the announce request. We then receive the reply
    # which we proceed to parse.
    req, transaction_id = udp_create_announce_request(connection_id,
                                                      info_hash,
                                                      sock.getsockname()[1])
    sock.sendto(req, (HOST, PORT))
    buf = sock.recvfrom(2048)[0]
    resp = udp_parse_announce_response(buf, transaction_id, info_hash)
    print "Response = ", resp
    print "Size of list = ", len(resp['peer_list'])
except socket.timeout:
    #print "Connection timeout to ", parsed_tracker.geturl()
    print "\n"

print "Sent:     {}".format(buf)
print "Received: {}".format(received)
