# ftraceroute

ftraceroute is a small traceroute program that sends ICMP echo probes to network hosts.
We try to use as little memory as possible.

Current maintainer: German-Service-Network
Website: https://www.gsnw.de/

## Installation

If you want to install ftraceroute from source, proceed as follows:

1. Run `./autogen.sh` (Only required for source code from the Git repository)
2. Run `./configure`
3. Run `make && make install`

The program can only be run as root.

## Usage

Help: `ftraceroute -h`

```
Usage: ftraceroute [options] <host>
Options:
  -h          Show this help message
  -v          Show version info
  -m <value>  Set max hops
  -c <value>  Set probe count
  -t <value>  Set timeout in ms
```