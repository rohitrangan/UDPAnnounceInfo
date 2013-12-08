#
# UDPAnnounceInfo - udptrack/__init__.py
#
# Author :- Rohit Rangan
# Date   :- 07-12-2013
#
# This file is part of UDPAnnounceInfo.
#
# UDPAnnounceInfo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# UDPAnnounceInfo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with UDPAnnounceInfo. If not, see <http://www.gnu.org/licenses/>.
#
# udptrack/__init__.py - Connecting to a UDP tracker given the info_hash and
# tracker URL. We create and parse the UDP packets as per the instructions
# given in - http://xbtt.sourceforge.net/udp_tracker_protocol.html
#
# TODO - Implement announce and scrape for the http protocol.
# TODO - Implement a better way to resolve timeouts.
#
# Original code from https://github.com/erindru/m2t/blob/master/m2t/scraper.py

import binascii, urllib, socket, random, struct

from urlparse import urlparse

def announce(tracker, info_hash):
    """
    Returns the announce list of a torrent given the tracker and info_hash.
    
    Args:
            tracker (str)  : The announce url for a tracker, usually taken
                             directly from the torrent metadata.
            info_hash (str): Torrent's info_hash to query the tracker for.

    Returns:
            A dictionary of the following form:-
            {
                'interval'  : 1803,
                'peers'     : 1,
                'seeds'     : 2,
                'peer_list' : [192.168.100.1:6554, 202.141.80.221:43321,
                               211.222.111.4:6332]
            }
    """
    tracker = tracker.lower()
    parsed = urlparse(tracker)
    if parsed.scheme == "udp":
        return announce_udp(parsed, info_hash)

    print "Unknown tracker scheme: %s" % parsed.scheme
    return None

def announce_udp(parsed_tracker, info_hash):
    # print "Announcing UDP: %s " % parsed_tracker.geturl()
    transaction_id = "\x00\x00\x04\x12\x27\x10\x19\x70";
    connection_id = "\x00\x00\x04\x17\x27\x10\x19\x80";
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(8)
    conn = (socket.gethostbyname(parsed_tracker.hostname), parsed_tracker.port)

    # Get connection ID.
    try:
        req, transaction_id = udp_create_connection_request()
        sock.sendto(req, conn);
        buf = sock.recvfrom(2048)[0]
        connection_id = udp_parse_connection_response(buf, transaction_id)
    
        # Creating, sending the announce request. We then receive the reply
        # which we proceed to parse.
        req, transaction_id = udp_create_announce_request(connection_id,
                                                          info_hash)
        sock.sendto(req, conn)
        buf = sock.recvfrom(2048)[0]
        return udp_parse_announce_response(buf, transaction_id, info_hash)
    except socket.timeout:
        print "Connection timeout to ", parsed_tracker.geturl()
        print "\n"
        return None

def udp_create_announce_request(connection_id, info_hash):
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
    port = 9999
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

def scrape(tracker, hashes):
    """
    Returns the list of seeds, peers and downloads a torrent info_hash has
    according to the specified tracker.

    Args:
            tracker (str): The announce url for a tracker, usually taken
                           directly from the torrent metadata
            hashes (list): A list of torrent info_hash's to query the tracker
                           for.

    Returns:
            A dict of dicts. The key is the torrent info_hash's from the
            'hashes' parameter and the value is a dict containing "seeds",
            "peers" and "complete".
            Eg:
            {
                "2d88e693eda7edf3c1fd0c48e8b99b8fd5a820b2": {"seeds": "34",
                                                             "peers": "189",
                                                             "complete": "9"},
                "8929b29b83736ae650ee8152789559355275bd5c": {"seeds": "12",
                                                             "peers": "0",
                                                             "complete": "29"}
            }
    """
    tracker = tracker.lower()
    parsed = urlparse(tracker)        
    if parsed.scheme == "udp":
        return scrape_udp(parsed, hashes)

    print "Unknown tracker scheme: %s" % parsed.scheme
    return None

def scrape_udp(parsed_tracker, hashes):
    #print "Scraping UDP: %s for %s hashes" % (parsed_tracker.geturl(),
    #                                          len(hashes))
    if len(hashes) > 74:
        raise RuntimeError("Only 74 hashes can be scraped on a UDP tracker "
                           "due to UDP limitations")
    transaction_id = "\x00\x00\x04\x12\x27\x10\x19\x70";
    connection_id = "\x00\x00\x04\x17\x27\x10\x19\x80";
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(8)
    conn = (socket.gethostbyname(parsed_tracker.hostname),
            parsed_tracker.port)

    # Get the connection ID.
    try:
        req, transaction_id = udp_create_connection_request()
        sock.sendto(req, conn);
        buf = sock.recvfrom(2048)[0]
        connection_id = udp_parse_connection_response(buf, transaction_id)

        # Creating, sending the scrape request. We then receive the reply
        # which we proceed to parse.
        req, transaction_id = udp_create_scrape_request(connection_id, hashes)
        sock.sendto(req, conn)
        buf = sock.recvfrom(2048)[0]
        return udp_parse_scrape_response(buf, transaction_id, hashes)
    except socket.timeout:
        print "Connection timeout to ", parsed_tracker.geturl()
        print "\n"
        return None

def udp_create_connection_request():
    # Refer to http://xbtt.sourceforge.net/udp_tracker_protocol.html
    connection_id = 0x41727101980
    action = 0x0
    transaction_id = udp_get_transaction_id()
    buf = struct.pack("!q", connection_id)
    buf += struct.pack("!i", action)
    buf += struct.pack("!i", transaction_id)
    return (buf, transaction_id)

def udp_parse_connection_response(buf, sent_transaction_id):
    # buf contains all the data sent byt the tracker.
    if len(buf) < 16:
        raise RuntimeError("Wrong response length getting connection id: %s" %
                            len(buf))
    action = struct.unpack_from("!i", buf)[0]
    res_transaction_id = struct.unpack_from("!i", buf, 4)[0]

    if res_transaction_id != sent_transaction_id:
        raise RuntimeError("Transaction ID does not match in connection"
                           " response! Expected %s, got %s"
                           % (sent_transaction_id, res_transaction_id))

    if action == 0x0:
        connection_id = struct.unpack_from("!q", buf, 8)[0]
        return connection_id
    elif action == 0x3:                
        error = struct.unpack_from("!s", buf, 8)
        raise RuntimeError("Error while trying to get a connection response: %s"
                            % error)
    pass

def udp_create_scrape_request(connection_id, hashes):
    # Refer to http://xbtt.sourceforge.net/udp_tracker_protocol.html
    action = 0x2
    transaction_id = udp_get_transaction_id()
    buf = struct.pack("!q", connection_id)
    buf += struct.pack("!i", action)
    buf += struct.pack("!i", transaction_id)

    for hash in hashes:                
        hex_repr = binascii.a2b_hex(hash)
        buf += struct.pack("!20s", hex_repr)
    
    return (buf, transaction_id)

def udp_parse_scrape_response(buf, sent_transaction_id, hashes):
    # buf contains all the data sent by the tracker.
    if len(buf) < 16:
        raise RuntimeError("Wrong response length while scraping: %s" %
                            len(buf))
    action = struct.unpack_from("!i", buf)[0]
    res_transaction_id = struct.unpack_from("!i", buf, 4)[0]

    if res_transaction_id != sent_transaction_id:
        raise RuntimeError("Transaction ID doesnt match in scrape response! "
                           "Expected %s, got %s" % (sent_transaction_id,
                                                    res_transaction_id))
    if action == 0x2:
        ret = {}
        offset = 8;
        for hash in hashes:
            seeds = struct.unpack_from("!i", buf, offset)[0]
            offset += 4
            complete = struct.unpack_from("!i", buf, offset)[0]
            offset += 4
            leeches = struct.unpack_from("!i", buf, offset)[0]
            offset += 4
            ret[hash] = { "seeds" : seeds, "peers" : leeches,
                          "complete" : complete }
        return ret
    elif action == 0x3:
        # An error occured. Try and extract the error string.
        error = struct.unpack_from("!s", buf, 8)
        raise RuntimeError("Error while scraping: %s" % error)

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
