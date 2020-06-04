import re
from ptrace.ctypes_tools import (truncateWord, bytes2word, formatWordHex)
from ptrace.error import PtraceError

from ptrace.debugger.process import PtraceProcess

REGISTER_REGEX = re.compile(r"\$[a-z]+[a-z0-9_]+")
from logging2 import warning

ptraceProc_g = None  # ugly but easy passing of proc to readRegister


def readRegister(regs):
    if ptraceProc_g is None:
        raise ValueError("no ptrace Process")
    name = regs.group(0)[1:]
    value = ptraceProc_g.getreg(name)
    return str(value)


SYMBOL_REGEX = re.compile(r"[a-zA-Z]+"
                          r"(:[a-zA-Z]+)?")


def parseInteger(text, procWrap=None):
    global ptraceProc_g
    ptraceProc_g= procWrap.ptraceProcess if procWrap else None

    # Remove spaces and convert to lower case
    text = text.strip()
    if " " in text:
        raise ValueError("Space are forbidden: %r" % text)
    text = text.lower()
    orig_text = text

    # replace symbols by their value
    def readSymbols(symbol):
        text = symbol.group(0)
        if procWrap is None:
            return text
        else:
            try:
                return str(procWrap.programinfo.getAddrOf(text))
            except ValueError as e:
                print(e)
                return text

    # Replace hexadecimal numbers by decimal numbers
    def readHexadecimal(regs):
        text = regs.group(0)
        if text.startswith("0x"):
            text = text[2:]
        elif not re.search("[a-f]", text):
            return text
        value = int(text, 16)
        return str(value)


    symbol_regex = r"(?<!0x)[a-zA-Z][a-zA-Z0-9_]*"  # a symbol or library should not start with a number
    symbol_regex_with_library = symbol_regex + r"(:" + symbol_regex + ")?"

    text = re.sub(r"(?:0x)[0-9a-f]+", readHexadecimal, text)
    text = re.sub(symbol_regex_with_library, readSymbols, text)

    # Replace registers by their value
    text = REGISTER_REGEX.sub(readRegister, text)


    # Reject invalid characters
    if not re.match(r"^[()<>+*/&0-9-]+$", text):
        raise ValueError("Invalid expression: %r" % orig_text)

    # Use integer division (a//b) instead of float division (a/b)
    text = text.replace("/", "//")

    # Finally, evaluate the expression
    is_pointer = text.startswith("*")
    if is_pointer:
        text = text[1:]
    try:
        value = eval(text)
        value = truncateWord(value)
    except SyntaxError:
        raise ValueError("Invalid expression: %r" % orig_text)
    if is_pointer:
        assert isinstance(ptraceProc_g, PtraceProcess)
        # value = ptraceProc_g.readWord(value)

        try:
            value = ptraceProc_g.readBytes(value, 8)
            value = bytes2word(value)
        except PtraceError as e:
            warning(str(e))
            value = 0

    return value


def parseBytes(text):
    value = eval(text)
    return value
