UDPAnnounceInfo
===============

##Instructions for use
1. Run udp\_track\_announce.py in the terminal using the following command
   "python udp\_track\_announce.py -h". This will display the help for the
   program and instructions for use.

2. Torrent file name must be given. If both the announce and scrape options
   are present, only scrape data is obtained.

##TODO
1. When there is a timeout, the program exits without getting information
   from any subsequent trackers.

2. The user should be able to provide external trackers from the command line.

3. Starting separate threads for every tracker to make the process faster.

4. Getting tracker data using http.
