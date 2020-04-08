from select import poll


# https://stackoverflow.com/questions/1456373/two-way-reverse-map
class BiDict(dict):
    def __setitem__(self, key, value):
        # Remove any previous connections with these values
        if key in self or value in self:
            raise KeyError("key or value already present!")

        dict.__setitem__(self, key, value)
        dict.__setitem__(self, value, key)

    def __delitem__(self, key):
        dict.__delitem__(self, self[key])
        dict.__delitem__(self, key)

    def __len__(self):
        """Returns the number of connections"""
        return dict.__len__(self) // 2


class PaulaPoll:

    def __init__(self):
        self.pollObj= poll()
        self.dict = BiDict()

    def register(self,fd,name):
        self.dict[fd]=name
        return self.pollObj.register(fd)

    def unregister(self,name_or_fd):
        assert isinstance(name_or_fd, int) or isinstance(name_or_fd, str)
        assert name_or_fd in self.dict
        del self.dict[name_or_fd]

    def poll(self):         # get name, fd and event
        ret= self.pollObj.poll()
        return list((self.dict[fd], fd, event) for fd, event in ret)
