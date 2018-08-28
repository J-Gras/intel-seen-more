# Intel Seen More

This package provides additional seen scripts for Bro's intelligence framework. It implements the following functionalities:

 * `udp`: Sees originator and responder of UDP connections. **Note:** The script uses the potentially expensive event `new_connection`.

 * `icmp-ping`: Sees originator and responder of ICMP echo requests and replies. **Note:** The script uses potentially expensive events.

 * `effective_dns`: Introduces the `Intel::EFFECTIVE_DOMAIN` indicator type for effective domains. For example "wikipedia.org" will match "www.wikipedia.org" and other subdomains. **Note:** The scripts require the DomainTLD package.

 * `conn-tcp`: Introduces the `Intel::CONN_TCP` indicator type supporting `<IP>:<Port>` indicators for *established* TCP connections.

## Installation

The scripts are available as package for the [Bro Package Manager](https://github.com/bro/package-manager) and can be installed using the following command:
```
bro-pkg install intel-seen-more
```

## Usage

By default no script is loaded! To load all scripts add the following to your `local.bro`:
```
@load packages
@load packages/intel-seen-more/seen
```

Seen scripts can also be loaded selectively:
```
@load packages
@load packages/intel-seen-more/seen/udp
@load packages/intel-seen-more/seen/effective-dns
```
