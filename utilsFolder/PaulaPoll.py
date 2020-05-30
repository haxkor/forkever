from select import poll, POLLIN, POLLPRI


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
        self.pollObj = poll()
        self.name_dict = BiDict()
        self.mask = POLLIN | POLLPRI

    def register(self, fd, name, mask=None):
        if mask is None:
            mask = self.mask

        name_in = name in self.name_dict
        fd_in = fd in self.name_dict
        if name_in != fd_in:
            raise KeyError("only one of (key,value) is already present")

        if not name_in:
            self.name_dict[fd] = name
        return self.pollObj.register(fd, mask)

    def unregister(self, name_or_fd):
        assert isinstance(name_or_fd, int) or isinstance(name_or_fd, str)
        assert name_or_fd in self.name_dict

        if isinstance(name_or_fd,str):
            unreg=self.name_dict[name_or_fd]
        else:
            unreg=name_or_fd

        self.pollObj.unregister(unreg)
        del self.name_dict[name_or_fd]

    def poll(self,timeout=None):  # get name, fd and event
        ret = self.pollObj.poll(timeout)
        return list((self.name_dict[fd], fd, event) for fd, event in ret)
