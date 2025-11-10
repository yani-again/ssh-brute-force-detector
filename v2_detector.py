import sys

f = open("./detector.config")
config = f.read().split('\n')
f.close()

# constants
VALID_OPTIONS = [
        "FILE_TYPE", "INTERVAL", "MAX_ATTEMPTS", "SERVER", \
        "GENERATE_COMMAND", "LOG_FILE", "EXCLUDE_IP", \
        "BEFORE", "AFTER"
        ]

YEAR_IN_SECONDS = 31556952
MONTH_IN_SECONDS = 2629746
DAY_IN_SECONDS = 86400
HOUR_IN_SECONDS = 3600
MINUTE_IN_SECONDS = 60

DAYS_IN_MONTH = {
        'Jan': '31',
        'Feb': '28',
        'Mar': '31',
        'Apr': '30',
        'May': '31',
        'Jun': '30',
        'Jul': '31',
        'Aug': '31',
        'Sep': '30',
        'Oct': '31',
        'Nov': '30',
        'Dec': '31'
        }

# set default options
options = {}
for line in config:
    if len(line) > 0 and line[0] != '#':
        option = line.split('=')[0].strip()
        values = line.split('=')[1].strip()
        
        # split comma-separated options into lists
        if ',' not in values:
            options[option] = values
        else:
            options[option] = [value.strip() for value in values.split(',')]

# set user-defined options
for i in range(1, len(sys.argv), 2):
    if sys.argv[i][:2] == '--' and sys.argv[i][2:].upper() in VALID_OPTIONS:

        if ',' not in sys.argv[i+1]:
            options[sys.argv[i][2:].upper()] = sys.argv[i + 1]
        else:
            options[sys.argv[i][2:].upper()] = \
                    [value.strip() for value in sys.argv[i + 1].split(',')]
    else:
        print("Invalid option:", sys.argv[i])
        exit()

# ----------------
# helper functions
# ----------------

# convert date to seconds
def dtos(date):
    date_s = (int(date[:2]) - 1) * MONTH_IN_SECONDS + \
                    (int(date[3:5]) - 1) * DAY_IN_SECONDS + \
                    int(date[6:8]) * HOUR_IN_SECONDS + \
                    int(date[9:11]) * MINUTE_IN_SECONDS + \
                    int(date[12:])
    return date_s

# convert time boundaries to seconds
options["BEFORE"] = dtos(options["BEFORE"])
options["AFTER"] = dtos(options["AFTER"])

# get difference between 2 timestamps in seconds
def time_difference(d1, d2):
    d1_in_seconds = dtos(d1)
    d2_in_seconds = dtos(d2)

    # if d2 < d1, a New Year's was in between
    if d2_in_seconds < d1_in_seconds:
        d2_in_seconds += YEAR_IN_SECONDS
    
    return d2_in_seconds - d1_in_seconds

# formatting for the standard sshd log file
def format_sshd(f):
    log = f.split('\n')
    log_formatted = []

    for entry in log:
        server_name = ""
        try:
            server_name = entry.split(' ', 4)[3]
        except:
            continue

        if "Failed password for" in entry and \
                options["SERVER"] == server_name:
            parts = entry.split(' ', 3)
            month = list(DAYS_IN_MONTH).index(parts[0])
            day = parts[1] if len(parts[1]) == 2 else '0' + parts[1]

            date_time = str(month + 1) + ':' + day + ':' + parts[2]

            # get failed IPs for password and key attempts
            ip = entry.split(": Failed ")[1].split(" from ")[1].split(" port")[0]
            
            log_formatted.append([date_time, ip])
    return log_formatted

# check if ip has failed repeatedly in quick succession
def check_ip(time):
    fast_fail_count = 0
    for i in range(1, len(time)):
        if not date_in_range(time[i]):
            continue
        if abs(time_difference(time[i - 1], time[i])) < int(options["INTERVAL"]):
            fast_fail_count += 1
        if fast_fail_count >= int(options["MAX_ATTEMPTS"]):
            return True
    return False

def date_in_range(date):
    date_s = dtos(date)

    if (date_s - options["BEFORE"] < 0) and (date_s - options["AFTER"] > 0):
        return True
    return False

# -------------
# main logic
# -------------

def run_detector():
    try:
        f = open(options["LOG_FILE"])
    except:
        print("Couldn't find file:", options["LOG_FILE"])
        exit()

    if options["FILE_TYPE"].lower() == "sshd":
        log = format_sshd(f.read())
    else:
        print("Unsupported file type:", options["FILE_TYPE"])
        f.close()
        exit()

    f.close()

    failed_ips = {}
    malicious_ips = []
    for entry in log:
        if entry[1] not in failed_ips:
            failed_ips[entry[1]] = []
        failed_ips[entry[1]].append(entry[0])

    for ip in failed_ips:
        if len(failed_ips[ip]) > int(options["MAX_ATTEMPTS"]) \
                and check_ip(failed_ips[ip]) == True \
                and ip not in options["EXCLUDE_IP"]:
            malicious_ips.append(ip)
    return malicious_ips

if __name__ == "__main__":
    malicious_ips = run_detector()
    if len(malicious_ips) > 0:
        for ip in malicious_ips:
            print("Malicious IP detected:", ip)
    else:
        print("No malicious IPs detected!")

    if "GENERATE_COMMAND" in options:
        if options["GENERATE_COMMAND"] == "iptables":
            print("\niptables command(s) to block malicious IPs:")
            for ip in malicious_ips:
                print("sudo iptables -A INPUT -s " + ip + \
                        " -p tcp -m tcp --dport <your_ssh_port> -j DROP")

