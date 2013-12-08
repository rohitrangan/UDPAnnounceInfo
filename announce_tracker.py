from tracker.udp_tracker import UDPTracker, MyUDPHandler

HOST, PORT = "localhost", 9999
server = UDPTracker((HOST, PORT), MyUDPHandler,
                    trackers_url=["udp://tracker.publicbt.com:80/announce"])
# server = SocketServer.UDPServer((HOST, PORT), MyUDPHandler)
server.serve_forever()
