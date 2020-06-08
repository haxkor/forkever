from utilsFolder.MapsReader import getMappings
from itertools import groupby
import pwn
from weakref import ref

from logging2 import debug
# from ProcessWrapper import ProcessWrapper
from utilsFolder.Parsing import parseInteger

from Constants import PRINT_OTHER_CANDIDATES


class ProgramInfo:

    def __init__(self, path_to_hack: str, pid: int, procWrap):
        self.pid = pid
        self.path_to_hack = path_to_hack

        self.elfDict = dict()
        self.baseDict = dict()

        self.elf = self._getElf(path_to_hack) if path_to_hack else None

        self.procWrap_ref = ref(procWrap)

    def _getElf(self, lib: str):
        """ given a library name, load it as an pwn.ELF object and determine the baseAdress.
        Makes sure there are not multiple librarys with the name
        """

        if lib in self.elfDict:
            return self.elfDict[lib]
        else:
            maps = getMappings(self.pid, lib)
            if len(maps) == 0:
                raise ValueError("lib not found")

            # make sure there arent multiple libarys with the given infix
            sortfunc = lambda mapping: mapping.pathname
            maps = sorted(maps, key=sortfunc)  # groupby requires sorted list
            maps_group_pathname = []
            for _, g in groupby(maps, sortfunc):
                maps_group_pathname.append(list(g))
            if len(maps_group_pathname) != 1:
                assert len(maps_group_pathname) > 0
                raise ValueError("multiple libs with what name")

            # create ELF
            full_path = maps_group_pathname[0][0].pathname
            if full_path in self.elfDict:
                return self.elfDict[full_path]

            elf = pwn.ELF(full_path, False)
            self.elfDict[lib] = elf
            self.elfDict[full_path] = elf

            # find base adress
            keyfunc = lambda mapping: mapping.start
            baseAd = min(maps_group_pathname[0], key=keyfunc).start

            if not elf.pie:
                baseAd = 0
            self.baseDict[lib] = baseAd
            elf.base = baseAd

            return elf

    def getAllSymbols(self, lib):
        elf = self._getElf(lib)
        return elf.symbols

    def getAddrOf(self, symbol: str, lib=None):
        if lib is None:
            lib = self.elf.path
        if ":" in symbol:
            lib, _, symbol = symbol.partition(":")  # libc:free

        elf = self._getElf(lib)

        #print(elf.symbols)

        find_cands = lambda x: symbol in x
        candidates = list(filter(find_cands, elf.symbols.keys()))

        if len(candidates) == 0:
            raise ValueError("no symbol for %s:%s found" % (lib, symbol))
        else:
            candidates = sorted(candidates, key=len)
            if len(candidates) > 1 and PRINT_OTHER_CANDIDATES:
                others = list((cand, hex(elf.symbols[cand])) for cand in candidates)
                print("chose %s out of %s" % (candidates[0], others))

            offset = elf.base if elf.pie else 0
            final_cand = candidates[0]
            if len(final_cand) / len(symbol) > 1.5:
                raise ValueError("shortest possible candidate %s still too long.\n"
                                 "other candidates: %s" % (final_cand, candidates[:10]))

            symbol_ad = elf.symbols[final_cand]

            return symbol_ad + offset

    def getElfStart(self):
        """returns virtual address of where the ELF starts"""
        starts= [mapping.start for mapping in getMappings(self.pid, self.path_to_hack)]
        return min(starts)


    def where(self, ip: int):
        """ finds the symbol for the respective virtual adress"""
        from operator import itemgetter
        found = None
        for mapping in getMappings(self.pid):
            if mapping.start <= ip <= mapping.end:
                found = mapping
        if not found:
            # TODO libc has a segment (where free_hook is) that has no name in maps
            raise ValueError("adress is not in virtual adress space")

        # find smaller symbols
        debug(found.pathname)
        elf = self._getElf(found.pathname)
        symbols = list((symbolname, symbol_ad + elf.base) for
                       (symbolname, symbol_ad) in elf.symbols.items())
        filter_func = lambda sym_ad_tuple: sym_ad_tuple[1] <= ip
        symbols_smaller = filter(filter_func, symbols)

        # biggest matching is the one we need
        symbol = max(symbols_smaller, key=itemgetter(1))
        return symbol  # get symbol string
