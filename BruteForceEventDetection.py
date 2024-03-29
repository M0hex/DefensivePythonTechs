import win32evtlog
import pywintypes
import os

server ="localhost"
logtype = "Security"
flags = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ

def QueryEventLog(eventID, filename=None):
    logs= []
    try:
   

        if not filename:
            h= win32evtlog.OpenEventLog(server,logtype)
        else:
            h = win32evtlog.OpenBackupEventLog(server,filename)
    
        while True:
            events = win32evtlog.ReadEventLog(h,flags,0)
            if events:
                for event in events:
                    if event.EventID == eventID:
                        logs.append(event)
            else:
                break
    except pywintypes.error as e:
        print(f"An error occurred: {e}")
    return logs

def DetectBruteForce(filename=None):
    failures = {}
    events = QueryEventLog(4625,filename)
    for event in events:
        if int(event.StringInserts[10]) in [3,8,5,10]:
            account = event.StringInserts[5]
            if account in failures:
                failures[account] += 1
            else:
                failures[account] = 1
    return failures
    



# Original filename
filename = "%SystemRoot%\System32\Winevt\Logs\Security.evtx"

# Expand environment variables in the filename
expanded_filename = os.path.expandvars(filename)
failures = DetectBruteForce(expanded_filename)
for account in failures:
    print("%s: %s failed logins" % (account,failures[account]))
