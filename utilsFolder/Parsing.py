import re
from ptrace.ctypes_tools import (truncateWord,
                                 formatWordHex, formatAddress, formatAddressRange, word2bytes)

from ptrace.debugger.process import PtraceProcess
REGISTER_REGEX = re.compile(r"\$[a-z]+[a-z0-9_]+")


ptraceProc_g=None   # ugly but easy passing of proc to readRegister


def readRegister(regs):
    if ptraceProc_g is None:
        raise ValueError("no ptrace Process")
    name = regs.group(0)[1:]
    value = ptraceProc_g.getreg(name)
    return str(value)


def parseInteger(text, ptraceProc=None):
    global ptraceProc_g
    ptraceProc_g=ptraceProc
    # Remove spaces and convert to lower case
    text = text.strip()
    if " " in text:
        raise ValueError("Space are forbidden: %r" % text)
    text = text.lower()

    # Replace registers by their value
    orig_text = text
    text = REGISTER_REGEX.sub(readRegister, text)

    # Replace hexadecimal numbers by decimal numbers
    def readHexadecimal(regs):
        text = regs.group(0)
        if text.startswith("0x"):
            text = text[2:]
        elif not re.search("[a-f]", text):
            return text
        value = int(text, 16)
        return str(value)
    text = re.sub(r"(?:0x)?[0-9a-f]+", readHexadecimal, text)

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
        value = ptraceProc_g.readWord(value)
    return value

def parseBytes(text):
    value = eval(text)
    return value