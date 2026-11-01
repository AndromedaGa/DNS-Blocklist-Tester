# DNS Blocklist Tester

A simple Bash script to test domains from DNS blocklists and check whether they are blocked by your DNS server.

I created this script to test HaGeZi blocklists using my FRITZ!Box DNS server.

Pls change the DNS Server according to yours. 

## Features

* Reads blocklist files from a folder.
* Supports multiple blocklist formats.
* Tests both IPv4 (A) and IPv6 (AAAA) records.
* Runs multiple DNS queries in parallel.
* Shows live progress, speed and estimated time remaining.
* Saves domains that successfully resolve to a CSV file.

## Requirements

* Ubuntu or another Linux distribution.
* Bash
* `dig` (dnsutils)
* `awk`, `sort`, `xargs` and `flock`

Install the required DNS utility:

```bash
sudo apt install dnsutils
```

## Usage

1. Clone this repository:

```bash
git clone YOUR_REPOSITORY_LINK
```

2. Open the project folder:

```bash
cd DNS_Test
```

3. Create a folder named `blocklists` and put your blocklist files inside it.

4. Run the script:

```bash
chmod +x test-blocklists.sh
./test-blocklists.sh
```

5. Enter the number of parallel workers when prompted.

## DNS Server

By default, the script uses:

```bash
10.0.100.1
```

Change this address in the script if you want to use a different DNS server.

## Results

The script generates:

```text
resolved-domains.csv
```

The CSV contains:

* Domain
* Source file
* IPv4 address (A)
* IPv6 address (AAAA)

## Notes

* Only successfully resolved domains are saved.
* Blocked and inconclusive results are counted separately.
* Results depend on the DNS server's blocking behavior.
