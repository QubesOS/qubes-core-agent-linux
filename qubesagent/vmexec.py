import sys
import os
import re


class DecodeError(ValueError):
    pass


ESCAPE_RE = re.compile(br'--|-([A-F0-9]{2})')


def decode_part(part):
    if not re.match(r'^[a-zA-Z0-9._-]*$', part):
        raise DecodeError('illegal characters found')

    part = part.encode('ascii')

    # Check if no '-' remains outside of legal escape sequences.
    if b'-' in ESCAPE_RE.sub(b'', part):
        raise DecodeError("'-' can be used only in '-HH' or '--'")

    def convert(m):
        if m.group(0) == b'--':
            return b'-'
        num = int(m.group(1), 16)
        return bytes([num])

    return ESCAPE_RE.sub(convert, part)


def decode(arg):
    '''
    Decode the argument for executing. The format is as follows:
    - individual parts are split by '+'
    - bytes are escaped as '-HH' (where HH is hex code, capital letters only)
    - literal '-' is encoded as '--'
    - otherwise, only [a-zA-Z0-9._] are allowed

    :param arg: argument, as a string
    :returns: list of exec arguments (each as bytes)
    '''
    return [decode_part(part) for part in arg.split('+')]


def main(argv=sys.argv):
    if len(argv) != 2:
        print('This service requires exactly one argument', file=sys.stderr)
        exit(1)
    try:
        command = decode(argv[1])
    except DecodeError as e:
        print('Decode error: {}'.format(e), file=sys.stderr)
        exit(1)
    os.execvp(command[0], command)


if __name__ == '__main__':
    main()
