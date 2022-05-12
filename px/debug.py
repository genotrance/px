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

    stdout = None
    stderr = None
    file = None
    name = ""
    mode = ""

    def __init__(self, name = "", mode = ""):
        if isinstance(sys.stdout, Debug):
            # Restore stdout since child inherits parent's Debug instance on Linux
            sys.stderr = sys.stdout.stderr
            sys.stdout = sys.stdout.stdout

        self.stdout = sys.stdout
        self.stderr = sys.stderr
        if len(name) != 0:
            self.name = name
            self.mode = mode
            self.reopen()

    def reopen(self):
        "Restart debug redirection - can be called after self.close()"
        sys.stdout = self
        sys.stderr = self
        if len(self.name) != 0:
            self.file = open(self.name, self.mode)

    def close(self):
        "Turn off debug redirection"
        sys.stdout = self.stdout
        sys.stderr = self.stderr
        if len(self.name) != 0:
            self.file.close()

    def write(self, data):
        "Write data to debug file and stdout"
        if self.file is not None:
            try:
                self.file.write(data)
            except:
                pass
        if self.stdout is not None:
            self.stdout.write(data)
        self.flush()

    def flush(self):
        "Flush data to debug file and stdout after write"
        if self.file is not None:
            self.file.flush()
            os.fsync(self.file.fileno())
        if self.stdout is not None:
            self.stdout.flush()

    def print(self, msg):
        "Print message to stdout and debug file if open"
        offset = 0
        tree = ""
        while True:
            try:
                name = sys._getframe(offset).f_code.co_name
                offset += 1
                if name != "print":
                    tree = "/" + name + tree
                if offset > 3:
                    break
            except ValueError:
                break
        sys.stdout.write(
            multiprocessing.current_process().name + ": " +
            threading.current_thread().name + ": " + str(int(time.time())) +
            ": " + tree + ": " + msg + "\n")

    def get_print(self):
        "Get self.print() method to call directly as print(msg)"
        return self.print
