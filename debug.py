"Direct stdout and stderr to a file for debugging"

import multiprocessing
import os
import sys
import threading
import time

# Print if possible
def pprint(*objs):
    "Catch exception if print not possible while running in the background"
    try:
        print(*objs)
    except:
        pass

class Debug(object):
    "Redirect stdout to a file for debugging"

    def __init__(self, name, mode):
        self.name = name
        self.mode = mode
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        self.reopen()

    def reopen(self):
        "Restart debug redirection - can be called after self.close()"
        sys.stdout = self
        sys.stderr = self
        self.file = open(self.name, self.mode)

    def close(self):
        "Turn off debug redirection"
        sys.stdout = self.stdout
        sys.stderr = self.stderr
        self.file.close()

    def write(self, data):
        "Write data to debug file and stdout"
        try:
            self.file.write(data)
        except:
            pass
        if self.stdout is not None:
            self.stdout.write(data)
        self.flush()

    def flush(self):
        "Flush data to debug file and stdout after write"
        self.file.flush()
        os.fsync(self.file.fileno())
        if self.stdout is not None:
            self.stdout.flush()

    def print(self, msg):
        "Print message to stdout and debug file if open"
        sys.stdout.write(
            multiprocessing.current_process().name + ": " +
            threading.current_thread().name + ": " + str(int(time.time())) +
            ": " + sys._getframe(1).f_code.co_name + ": " + msg + "\n")

    def get_print(self):
        "Get self.print() method to call directly as print(msg)"
        return self.print
