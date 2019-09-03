# pcap2udp

A simple tool to read microsecond-based pcap file frame by frame, remove N first bytes for each, then send each to one specified UDP socket, respecting timestamps.

# Usage

```
$ pcap2udp --help
pcap2udp 0.1.0

USAGE:
    pcap2udp <pcap-file> <skip-bytes> <bind-addr> <send-to>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <pcap-file>     
    <skip-bytes>    
    <bind-addr>     
    <send-to>       
```

Example: `./pcap2udp some_file.cap 42 127.0.0.1:0 127.0.0.1:1234`

The file should probably be pre-filtered in Wireshark. Wireshark can also rell the required offset (`skip_bytes`) inside packets.

# Prebuilt executables

On Github releases there should be following files:

```
pcap2udp_arm_android  pcap2udp_linux64        pcap2udp_linuxstatic64  pcap2udp_win32.exe
pcap2udp_arm_static   pcap2udp_linuxstatic32  pcap2udp_mac            pcap2udp_win64.exe
```

# See also

* [udpreplay](https://github.com/rigtorp/udpreplay)
