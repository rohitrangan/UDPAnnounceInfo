#!/usr/bin/python
#
# UDPAnnounceInfo - udp_announce_info.py
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
# udp_announce_info.py - Main file which is to be executed. Parses command
# line arguments and gives result. Use the option '-h' for help.
#
# TODO - Announce / Scrape each tracker on a different thread.
# TODO - Allow users to add external trackers through the command line.

from hashlib import sha1
from argparse import ArgumentParser

from bencode import bdecode, bencode
from udptrack import scrape, announce

# Creating an argument parser. Torrent file is necessary.
parser = ArgumentParser(description='Get UDP announce data from trackers for'
                        ' the given torrent file.')
parser.add_argument('filename', metavar='torrent_file', type=file, nargs=1,
                    help='Torrent File');
parser.add_argument('-s', '--scrape', action='store_true', help='Get scrape'
                    ' information.')
parser.add_argument('-a', '--announce', action='store_true', help='Get '
                    'announce information.')

# Parsing the arguments.
args = parser.parse_args()
torfile = args.filename[0]
# Contents of the torrent file.
torstring = torfile.read()

# We get a dictionary of the decoded torrent file.
rval = bdecode(torstring)
announce_list = rval['announce-list']
info_sha1_hash = sha1(bencode(rval['info']))
# The hexadecimal value of the SHA1 hash.
info_hash_val = info_sha1_hash.hexdigest()

# Getting scrape data. Scrape data only gives the number of peers, seeders and
# complete downloaders.
if args.scrape:
    for tracker in announce_list:
        print "For tracker ", tracker[0]
        scrape_dict = scrape(tracker[0], [info_hash_val])
        if scrape_dict is None:
            continue
        scrape_dict = scrape_dict[info_hash_val]
        print "Seeds     : ", scrape_dict['seeds']
        print "Peers     : ", scrape_dict['peers']
        print "Completed : ", scrape_dict['complete']
        print "\n"

# Getting announce data. We get the number of seeds, number of peers and the
# complete IP address (including the port number) of every peer.
if args.announce and (not args.scrape):
    for tracker in announce_list:
        print "For tracker ", tracker[0]
        scrape_dict = announce(tracker[0], info_hash_val)
        if scrape_dict is None:
            continue
        print "Seeds     : ", scrape_dict['seeds']
        print "Peers     : ", scrape_dict['peers']
        print "Peer List : "
        peer_list = scrape_dict['peer_list']
        for ele in peer_list:
            print ele, "  "
        print "\n"
