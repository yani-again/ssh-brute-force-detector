## Offline Python Brute-Force Detector
Small, standalone Python script which parses SSH log files (offline, not in
real time) and reports IPs that appear to be performing brute-force attempts.
Designed to improve my string-parsing skills as I prepared for a programming
exam at university.
<br>

#### New Changes
1. Added new options:
    - --BEFORE and --AFTER to search for a specific date range (*NOTE!* Use it
      by adding the FULL date in the format `MM:DD:HH:MM:SS`, use default value
      for reference in the config file)
    - --EXCLUDE\_IP to exclude IPs from the search, can be a comma-separated
      list to exclude multiple IPs

#### This Is Version 2.0
I rewrote the whole code from scratch for a few reasons:
1. It was rather messy
2. Improving it or adding new functionality will be annoying
3. I wanted to add some of the features I considered adding before

#### 1. Original Features:
- Parse standard SSH log files
- Configurable *(see `How To Run` section)*
- Output directly in the terminal or to a file using the Linux `>` operator

#### 2. New Features:
- Made the program more configureable
- Made a dedicated config file `detector.config`
- Option to generate an `iptables` command to block IPs deemed malicious

#### 3. Requirements
- Python 3 *(3.10+ recommended)*
- No mandatory extermal packages *(only uses `sys`)*

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
The new version is much more straightforward to run. Here's the overview:
```bash
python3 detector.py <options>
```

The currently available options are:
- --LOG\_FILE           the log file name (or path and name)
- --FILE\_TYPE          log file type, only accepts 'sshd' for now
- --INTERVAL            max time between failed attempts to class it as a
                        brute-force attempt
- --MAX\_ATTEMPTS       max failed attempts in quick succession to flag IP
- --SERVER              the server to scan for
- --GENERATE\_COMMAND   generate command to block malicious IPs, only accepts
                        'iptables' for now

Some of these options also have default values which you can edit
in `detector.config`:
- --LOG\_FILE           ssh.log
- --FILE\_TYPE          sshd
- --INTERVAL            5
- --MAX\_ATTEMPTS       10
- --SERVER              server

#### 6. Expected Log Formats
Currently, the only supported log format is the standard sshd log:
`Nov 4 00:00:01 server sshd[1001]: Server listening on 0.0.0.0 port 22`
Where you have:
- Date in the format `MMM DD`
- Time in the format `HH:MM:SS` as standard
- Server name after that
- A colon `:` separating the information of the entry
- Failed attempts are in the form "Failed \<...\> from \<ip\>"

*Note:* since the previous version, the date in `MMM DD` no longer has to be
padded with a 0 to the left if it is a single digit.

#### 7. Output
Outputs will take 1 of 2 forms:
1. `Malicious IP detected: x.x.x.x` if an IP is deemed malicious. This may
   produce several lines if multiple IPs seem suspicious
2. `No malicious IPs detected!` if no IPs are deemed malicious.
3. Additionally, lines with commands may be generated if the option is included

#### 8. Limitations
- As this is a project made for me to essentially learn Python, it is not
  designed to handle multi-GB log files and will likely run extremely slowly.

  The supplied `ssh.log` file is 404K and takes the program about 0.07s to
  parse, meaning a 1G log file will likely take around 30-40min to parse.

- If multiple users are sharing an IP through something like an NAT and they
  fail their logins in quick succession, it may be flagged as malicious

#### 10. Development Notes (Potential Future Features)
So far, I've already included a few of the original features I wanted to revisit
and include.

Future features may include:
- Adding even more options
- Produce commands to block IPs besides for apps beyond `iptables`
- Extend accepted file types
