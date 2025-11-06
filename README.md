## Offline Python Brute-Force Detector
Small, standalone Python script which parses any SSH log file (offline, not in
real time) and reports IPs that appear to be performing brute-force attempts.
Designed to improve my string-parsing skills as I prepared for a programming
exam at university.
<br>
#### 1. Overview
This tool takes in 2 options:
1. Mode
2. Server name
It then parses a SSH log file (I conveniently supplied one in this repo), and
performs checks based off the input options.

It works in the terminal, checking for repeated failed attempts within a set
interval, returning (allegedly) malicious IPs upon detection, otherwise
informing you no IPs were deemed to be malicious.

It's designed to work entirely offline, though with some tinkering it could be
configured to work on a live & ongoing log through something like a daemon
script.

This is *not* supposed to be a replacement to anything like `fail2ban`, it's
purely a lightweight detector with a single function which I built in order to
practice my string-parsing and general Python skills for an upcoming exam at
university

#### 2. Features
- Parse standard SSH log files you see in places like `/var/log/auth.log`
  *(Debian/Ubuntu)* or through `journalctl` on Arch Linux.
- Configurable threshold and server name *(see `How To Run` section)*
- Output directly in the terminal or to a file using the Linux `>` operator

#### 3. Requirements
- Python 3 *(3.10+ recommended)*
- No mandatory external packages *(uses `sys` only)*

#### 4. Installation
Clone the repo or copy this script in a suitable location:
```bash
git clone https://github.com/yani-again/ssh-brute-force-detector.git
cd ssh-brute-force-detector
```
###### Optional: Set Up A Virtual Environment
```bash
git clone https://github.com/yani-again/ssh-brute-force-detector.git
cd ssh-brute-force-detector
python3 -m venv .venv
source .venv/bin/activate
```

#### 5. How To Run
Running it requires 2 options:
1. The mode (strict, normal, loose)
2. The name of the server you want to scan

Run the file like this:
```bash
python3 brute_force_detector.py <mode> <server name>
```

Example:
```bash
python3 brute_force_detector.py normal db-server
```

**NOTE!** The mode and server name have to be written in that order.

#### 6. Expected Log Formats
Currently, the only supported log format is this:
`Nov 04 00:00:01 server sshd[1001]: Server listening on 0.0.0.0 port 22`
Where you have:
- Date in the format 'MMM DD` *(It's important the day is 2-digits long, even if
  it has to be padded like `04` instead of just`4`)*
- Time in the format `HH:MM:SS` as standard
- Server name after that
- A colon `:` separating the information of the entry

#### 7. Configuration
Currently, the only way to configure the values is by editing the source code
directly.

The configureable values are:
- SSH_LOG:  name of the log file
- INTERVAL: time between failed attempts to be classed as brute-force
- SERVERS:  list of all server names in the log file
- MODES:    how many failed attempts in quick succession will flag an IP

#### 8. Output
Outputs will take 1 of 2 forms:
1. `Potential brute force from x.x.x.x` if an IP is deemed malicious. This may
   produce several lines if multiple IPs seem suspicious
2. `No brute force attacks detected.` if no IPs are deemed malicious.

#### 9. Limitations
- As this is a project made for me to essentially learn Python, it is not
  designed to handle multi-GB log files and will likely run extremely slowly.

  The supplied `ssh.log` file is 388Kb and takes the program about 0.07s to
  parse, meaning a 1Gb log file will likely take around 30-40min to parse.

- If the day is not padded with a zero to make it 2-digits, the
  program will fail.

- If multiple users are sharing an IP through something like an NAT and they
  fail their logins in quick succession, it may be flagged as malicious

#### 10. Development Notes (Potential Future Features)
1. Add more options *(e.g. select date range to check, exclude certain IPs,
   etc.)*
2. Create a dedicated config file to make configuration easier
3. Produce commands to block IPs *(e.g. iptables or firewalls)*
4. Extend accepted file types

