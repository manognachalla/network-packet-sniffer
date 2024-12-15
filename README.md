# network-packet-sniffer
works kinda like wireshark

only works on mac or linux systems because of the packet capturing libraries used
command to run: g++ -std=c++17 main.cpp cn.cpp -o output -lpcap
./output

packets captured are displayed in the terminal
the header details of the packets are logged into the text file "log.txt"

please wait for the packets to be captured before checking the log file for updated information.
