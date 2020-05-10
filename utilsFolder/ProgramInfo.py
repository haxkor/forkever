from utilsFolder.MapsReader import getMappings
from itertools import groupby
import pwn


class ProgramInfo:

    def __init__(self, path_to_hack: str, pid: int):
        self.pid = pid
        self.path_to_hack = path_to_hack

        self.elfDict = dict()
        self.baseDict = dict()

        self.elf=self._getElf(path_to_hack)



    def _getElf(self, lib: str):
        """ given a library name, load it as an pwn.ELF object and determine the baseAdress.
        Makes sure there are not multiple librarys with the name
        """


        if lib in self.elfDict:
            return self.elfDict[lib]
        else:
            maps = getMappings(self.pid, lib)
            if len(maps) == 0:
                raise ValueError("not found")

            # make sure there arent multiple libarys with the given infix
            sortfunc = lambda mapping: mapping.pathname
            maps = sorted(maps, key=sortfunc)   # groupby requires sorted list
            maps_group_pathname = []
            for _, g in groupby(maps, sortfunc):
                maps_group_pathname.append(list(g))
            if len(maps_group_pathname) != 1:
                assert len(maps_group_pathname) > 0
                raise ValueError("multiple libs with what name")

            # create ELF
            full_path= maps_group_pathname[0][0].pathname
            if full_path in self.elfDict:
                return self.elfDict[full_path]

            elf = pwn.ELF(full_path, False)
            self.elfDict[lib] = elf
            self.elfDict[full_path] = elf

            # find base adress
            keyfunc = lambda mapping: mapping.start
            baseAd = min(maps_group_pathname[0], key=keyfunc).start

            self.baseDict[lib] = baseAd
            elf.base = baseAd

            return elf

    def getAddrOf(self, symbol:str, lib=None):
        if lib is None:
            lib = self.elf.path
        elf=self._getElf(lib)

        find_cands = lambda x: symbol in x
        candidates = list(filter(find_cands, elf.symbols.keys()))

        if len(candidates) == 0:
            print("symbol not found")
        else:
            candidates = sorted(candidates, key=len)[0]
            if len(candidates) > 1:
                print("chose %s out of %s" % (candidates[0], candidates))

            offset = elf.base if elf.pie else 0
            return self.elf.symbols[candidates[0]] + offset
