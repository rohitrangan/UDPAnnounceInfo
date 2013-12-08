import struct
import socket
import binascii
import SocketServer

from udptrack import announce

class MyUDPHandler(SocketServer.BaseRequestHandler):
    """
    This class works similar to the TCP handler class, except that
    self.request consists of a pair of data and client socket, and since
    there is no connection the client address must be given explicitly
    when sending data back via sendto().
    """

    __tracker_connection_id = 0

    def handle(self):
        data = self.request[0]
        socket = self.request[1]

        perform_action = self.get_action_from_request(data)
        if perform_action == 0x0:
            send_data = self.handle_action_connect(data)
        elif perform_action == 0x1:
            send_data = self.handle_action_announce(data)
        elif perform_action == 0x2:
            send_data = self.handle_action_scrape(data)
        else:
            send_data = self.handle_action_error(data)

        if send_data is None:
            print "ERROR!!"
            send_data = self.handle_action_error(data)
            socket.sendto(send_datadata, self.client_address)
        else:
            socket.sendto(send_data, self.client_address)

    def handle_action_connect(self, data):
        if len(data) < 16:
            return None
        print "IN ACTION CONNECTION\n"
        offset = 0
        connection_id = struct.unpack_from("!q", data, offset)[0]
        print "Connection ID  = ", connection_id
        offset += 8
        action = struct.unpack_from("!i", data, offset)[0]
        print "Action         = ", action
        offset += 4
        transaction_id = struct.unpack_from("!i", data, offset)[0]
        print "Transaction ID = ", transaction_id

        # Adding peer to our connected list.
        conn_ret = self.server.add_peer_to_connected_list(self.client_address,
                                MyUDPHandler.__tracker_connection_id)
        if conn_ret == -1:
            print "\nError adding to connected list.\n"
            return self.handle_action_error(data)

        # Packing data to send back to the client.
        send_action = 0x0
        send_data = struct.pack("!i", send_action)
        send_data += struct.pack("!i", transaction_id)
        send_data += struct.pack("!q", MyUDPHandler.__tracker_connection_id)
        MyUDPHandler.__tracker_connection_id += 1
        return send_data

    def handle_action_announce(self, data):
        if len(data) < 98:
            return None
        print "IN ACTION ANNOUNCE"
        offset = 0
        connection_id = struct.unpack_from("!q", data, offset)[0]
        print "Connection ID  = ", connection_id
        offset += 8
        action = struct.unpack_from("!i", data, offset)[0]
        print "Action         = ", action
        offset += 4
        transaction_id = struct.unpack_from("!i", data, offset)[0]
        print "Transaction ID = ", transaction_id
        offset += 4
        info_hash = struct.unpack_from("!20s", data, offset)[0]
        print "info_hash      = ", binascii.b2a_hex(info_hash)
        offset += 20
        peer_id = struct.unpack_from("!20s", data, offset)[0]
        print "Peer ID        = ", peer_id
        offset += 20
        downloaded = struct.unpack_from("!q", data, offset)[0]
        print "Downloaded     = ", downloaded
        offset += 8
        left = struct.unpack_from("!q", data, offset)[0]
        print "Left           = ", left
        offset += 8
        uploaded = struct.unpack_from("!q", data, offset)[0]
        print "Uploaded       = ", uploaded
        offset += 8
        event = struct.unpack_from("!i", data, offset)[0]
        print "Event          = ", event
        offset += 4
        ip_addr = struct.unpack_from("!I", data, offset)[0]
        print "IP Address     = ", ip_addr
        offset += 4
        key = struct.unpack_from("!I", data, offset)[0]
        print "Key            = ", key
        offset += 4
        num_want = struct.unpack_from("!i", data, offset)[0]
        print "Num want       = ", num_want
        offset += 4
        port = struct.unpack_from("!H", data, offset)[0]
        print "Port           = ", port

        # Adding hash to open torrents list and checking whether connection ID
        # matches peer.
        conn_ret = self.server.check_peer_in_connected_list(
                                    self.client_address, connection_id)
        if conn_ret == -1:
            return self.handle_action_error(data)

        conn_ret = self.server.add_hash_torrent_list(binascii.b2a_hex(
                                                                info_hash))
        if conn_ret == -1:
            return self.handle_action_error(data)

        # We obtain torrent information from other torrent websites.
        # Packing data to send back to the client.
        conn_ret = self.server.populate_torrent_list(binascii.b2a_hex(
                                                     info_hash),
                                                     self.client_address)
        if conn_ret == -1:
            return self.handle_action_error(data)

        # Getting our announce reply.
        send_data = self.server.pack_announce_reply(binascii.b2a_hex(
                                                    info_hash), 0x1,
                                                    transaction_id)
        if send_data == -1:
            return self.handle_action_error(data)

        return send_data

    def handle_action_scrape(self, data):
        return data

    def handle_action_error(self, data):
        return data

    def get_action_from_request(self, data):
        return struct.unpack_from("!i", data, 8)[0]

class UDPTracker(SocketServer.UDPServer):
    """
    This class creates a new UDP tracker using the MyUDPHandler class.
    It inherits from SocketServer.UDPServer
    """

    def __init__(self, server_address, RequestHandlerClass,
                 bind_and_activate=True, trackers_url=None):
        SocketServer.UDPServer.__init__(self, server_address,
                                        RequestHandlerClass,
                                        bind_and_activate)
        self.__open_torrent_list = {}
        self.__connected_peer_list = {}
        self.__trackers_url = trackers_url

    def add_peer_to_connected_list(self, peer_ip_address, connection_id):
        if peer_ip_address in self.__connected_peer_list:
            return -1
        self.__connected_peer_list[peer_ip_address] = connection_id
        print "\nConnected Peer List is"
        print self.__connected_peer_list
        print
        return 0

    def check_peer_in_connected_list(self, peer_ip_address, connection_id):
        if self.__connected_peer_list[peer_ip_address] == connection_id:
            return 0
        else:
            return -1

    def add_hash_torrent_list(self, info_hash):
        if info_hash in self.__open_torrent_list:
            return -1

        info_file_name = "." + str(info_hash) + ".dat"
        f_tmp = open(info_file_name, 'w')
        self.__open_torrent_list[info_hash] = info_file_name
        print "\nOpen Torrent List is"
        print self.__open_torrent_list
        f_tmp.close()
        return 0

    def populate_torrent_list(self, info_hash, peer_ip_address):
        if info_hash not in self.__open_torrent_list:
            return -1
 
        if self.__trackers_url is None:
            torr_data_file = open(self.__open_torrent_list[info_hash], 'a')
            torr_data_file.write("1 0 1800\n")
            torr_data_file.write(str(peer_ip_address[0]) + ":" +
                                 str(peer_ip_address[1]))
            torr_data_file.close()
            return 0

        else:
            torr_data_file = open(self.__open_torrent_list[info_hash], 'w')
            announce_ele = []
            max_seeds_num = -1
            max_peers_num = -1
            max_interval = 0
            complete_peer_list = []

            for track_ele in self.__trackers_url:
                tmp_ele = announce(track_ele, info_hash)
                if tmp_ele is None:
                    continue

                if tmp_ele['interval'] > max_interval:
                    max_interval = tmp_ele['interval']
                if tmp_ele['seeds'] > max_seeds_num:
                    max_seeds_num = tmp_ele['seeds']
                if tmp_ele['peers'] > max_peers_num:
                    max_peers_num = tmp_ele['peers']
                complete_peer_list = set(complete_peer_list +
                                         tmp_ele['peer_list'])

            #max_peers_num += 1
            print
            print "Max Interval     = ", max_interval
            print "Max Seeds        = ", max_seeds_num
            print "Max Peers        = ", max_peers_num
            print "Peer List        = ", complete_peer_list
            print "Peer List Length = ", len(complete_peer_list)

            # Writing data to the file.
            torr_data_file.write(str(max_peers_num) + " " + str(max_seeds_num)
                                 + " " + str(max_interval) + "\n")
            for ele in complete_peer_list:
                torr_data_file.write(ele + "\n")
            #torr_data_file.write(str(peer_ip_address[0]) + ":" +
            #                     str(peer_ip_address[1]))

            torr_data_file.close()
            return 0

    def pack_announce_reply(self, info_hash, send_action, transaction_id):
        if info_hash not in self.__open_torrent_list:
            return -1

        print "\nIn pack announce reply - "
        torr_data_file = open(self.__open_torrent_list[info_hash], 'r')
        peer_num = torr_data_file.readline()
        peer_num_arr = peer_num.split(" ")
        send_leechers = int(peer_num_arr[0])
        send_seeders = int(peer_num_arr[1])
        send_interval = int(peer_num_arr[2])
        print "Send leechers = ", send_leechers
        print "Send seeders  = ", send_seeders
        print "Send interval = ", send_interval
        send_data = struct.pack("!i", send_action)
        send_data += struct.pack("!i", transaction_id)
        send_data += struct.pack("!i", send_interval)
        send_data += struct.pack("!i", send_leechers)
        send_data += struct.pack("!i", send_seeders)

        for line in torr_data_file:
            print "Line read = ", line
            peer_ip_arr = line.split(":")
            peer_ip = binascii.b2a_hex(socket.inet_aton(peer_ip_arr[0]))
            peer_ip = int(peer_ip, 16)
            peer_ip = struct.unpack_from("!i", struct.pack("!I", peer_ip))[0]
            print "Peer IP   = ", peer_ip
            peer_port = int(peer_ip_arr[1])
            print "Peer Port = ", peer_port
            send_data += struct.pack("!i", peer_ip)
            send_data += struct.pack("!H", peer_port)

        torr_data_file.close()
        print "Send data size = ", len(send_data)
        return send_data
