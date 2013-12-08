import struct
import SocketServer

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
        print "Data type is ", type(data)
        print "self.request is - ", self.request
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
        offset = 0
        connection_id = struct.unpack_from("!q", data, offset)[0]
        print "Connection ID  = ", connection_id
        offset += 8
        action = struct.unpack_from("!i", data, offset)[0]
        print "Action         = ", action
        offset += 4
        transaction_id = struct.unpack_from("!i", data, offset)[0]
        print "Transaction ID = ", transaction_id
        send_action = 0x0
        send_data = struct.pack("!i", send_action)
        send_data += struct.pack("!i", transaction_id)
        send_data += struct.pack("!q", MyUDPHandler.__tracker_connection_id)
        MyUDPHandler.__tracker_connection_id += 1
        return send_data

    def handle_action_announce(self, data):
        return data

    def handle_action_scrape(self, data):
        return data

    def handle_action_error(self, data):
        return data

    def get_action_from_request(self, data):
        return struct.unpack_from("!i", data, 8)[0]

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    server = SocketServer.UDPServer((HOST, PORT), MyUDPHandler)
    server.serve_forever()
