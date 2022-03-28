import multiprocessing
import os
import sys
import threading
import time

# Print if possible
def pprint(*objs):
    try:
        print(*objs)
    except:
        pass

class Debug(object):
    def __init__(self, name, mode):
        self.file = open(name, mode)
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self

    def close(self):
        sys.stdout = self.stdout
        sys.stderr = self.stderr
        self.file.close()

    def write(self, data):
        try:
            self.file.write(data)
        except:
            pass
        if self.stdout is not None:
            self.stdout.write(data)
        self.flush()

    def flush(self):
        self.file.flush()
        os.fsync(self.file.fileno())
        if self.stdout is not None:
            self.stdout.flush()

    def print(self, msg):
        sys.stdout.write(
            multiprocessing.current_process().name + ": " +
            threading.current_thread().name + ": " + str(int(time.time())) +
            ": " + sys._getframe(1).f_code.co_name + ": " + msg + "\n")

    def get_print(self):
        return self.print