import threading
from pythonping import ping

class ThreadS(threading.Thread):
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs={}, Verbose=None):
        threading.Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None
    
    def run(self):
        if self._target is not None:    #  and self.stopped()
            self._return = self._target(*self._args,
                                                **self._kwargs)
    
    def join(self, *args):
        threading.Thread.join(self, *args)
        return self._return
    

class KeepAliveDaemon(threading.Thread):
    '''TODO:
     - Cleanup parameters
     - Send termination signal when exception occurs
     '''
    def __init__(self, queue, group=None, target=None, name=None,
                 args=(), kwargs={}):
        threading.Thread.__init__(self, group, target, name, args, kwargs)

        self.queue = queue

    def run(self):
        arg = self.queue.get()
        while True:
            if arg is None:
                threading.Thread.join(self)
                self._return
            else:
                self.fun(arg)

    def fun(self, arg):
        ping(arg, verbose=True, timeout=2, size=1, count=2, interval=3) # , interval=3










    # def set_start(self):
    #     self._stop.set()

    # def set_stop(self):
    #     self._stop.set()

    # def start(self):
    #     return self._stop.isSet()

    # def stop(self):
    #     return self._stop.isSet()
