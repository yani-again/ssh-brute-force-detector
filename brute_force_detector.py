import sys

# configureable values
SSH_LOG = "ssh.log"
INTERVAL = 5
SERVERS = ['server']
MODES = {
        'strict': 3,
        'normal': 6,
        'loose': 20
        }

# DO NOT EDIT BELOW THIS LINE!

# constants
YEAR_IN_SECONDS = 31556952
MONTH_IN_SECONDS = 2629746
DAY_IN_SECONDS = 86400
HOUR_IN_SECONDS = 3600
MINUTE_IN_SECONDS = 60

DAYS_IN_MONTH = {
        'Jan': 31,
        'Feb': 28,
        'Mar': 31,
        'Apr': 30,
        'May': 31,
        'Jun': 30,
        'Jul': 31,
        'Aug': 31,
        'Sep': 30,
        'Oct': 31,
        'Nov': 30,
        'Dec': 31
        }

# call using file.py <mode> <server name>
try:
    MODE = sys.argv[1]
    SERVER = sys.argv[2]
except:
    print("Invalid options.")
    exit()

# checking inputs
if MODE not in MODES:
    print("Invalid mode.")
    print("Hint: try 'strict', 'normal', or 'loose'.")
    exit()

if SERVER not in SERVERS:
    print("Invalid server name. Have you configured the server names?")
    print("Hint: check the GitHub page.")
    exit()

# get the difference between 2 dates in seconds
# d1[0] = date MM:DD
# d1[1] = time HH:MM:SS
def time_difference(d1, d2):
    # calculate the entry timestamp in seconds
    d1_time_in_seconds = int(d1[0][:2]) * MONTH_IN_SECONDS + \
                        int(d1[0][3:]) * DAY_IN_SECONDS + \
                        int(d1[1][:2]) * HOUR_IN_SECONDS + \
                        int(d1[1][3:5]) * MINUTE_IN_SECONDS + \
                        int(d1[1][6:])

    d2_time_in_seconds = int(d2[0][:2]) * MONTH_IN_SECONDS + \
                        int(d2[0][3:]) * DAY_IN_SECONDS + \
                        int(d2[1][:2]) * HOUR_IN_SECONDS + \
                        int(d2[1][3:5]) * MINUTE_IN_SECONDS + \
                        int(d2[1][6:])

    # add 1 year worth of seconds to d2_time_in_seconds if d1's month is
    # greater (meaning the 2 dates are from different years, and d1 is
    # supposed to be the earlier date)
    if int(d1[0][:2]) > int(d2[0][:2]):
        d2_time_in_seconds += YEAR_IN_SECONDS

    return abs(d1_time_in_seconds - d2_time_in_seconds)

def analyse_entry(entries):
    time_differences = []
    quick_fails = 0

    for i in range(len(entries) - 1):
        # format time of 2 consecutive failed attempts
        d1 = [str(list(DAYS_IN_MONTH).index(entries[i][:3]) + 1) \
                + ':' + entries[i][4:6], \
                entries[i][7:15]]
        d2 = [str(list(DAYS_IN_MONTH).index(entries[i + 1][:3]) + 1) \
                + ':' + entries[i + 1][4:6], \
                entries[i + 1][7:15]]
        
        # compare how long between the 2 timestamps
        difference = time_difference(d1, d2)

        # flag quick successions of fails
        if difference < INTERVAL:
            quick_fails += 1
        if quick_fails >= MODES[MODE]:
            return 1
    return 0

f = open(SSH_LOG)
log = f.read().split('\n')
f.close()

failed_logins = {}
flagged = 0

# format log into usable data
for entry in log:
    if entry.find('Failed password for ') != -1:
        failed_time = entry.split(' ' + SERVER)[0]
        failed_ip = entry.split(' from ')[1].split(' port ')[0]

        if failed_ip not in failed_logins:
            failed_logins[failed_ip] = []
        failed_logins[failed_ip].append(failed_time)

for ip in failed_logins:
    # only check if failed logins are more than the set mode
    if len(failed_logins[ip]) >= MODES[MODE]:
        if analyse_entry(failed_logins[ip]):
            print("Potential brute force from", ip)
            flagged += 1

if flagged == 0:
    print("No brute force attacks detected.")

