import queue
import socket
import os

# https://stackoverflow.com/questions/17495877/
# python-how-to-wait-on-both-queue-and-a-socket-on-same-time

class PollableQueue(queue.Queue):
    def __init__(self):
        super().__init__()
        # Create a pair of connected sockets
        if os.name == 'posix':
            self._putsocket, self._getsocket = socket.socketpair()
        else:
            print("i only work on posix")
            exit(3)

    def fileno(self):
        return self._getsocket.fileno()

    def put(self, item):
        super().put(item)
        self._putsocket.send(b'x')

    def get(self):
        self._getsocket.recv(1)
        return super().get()
