from libnacl import nacl

#  String cmp


def crypto_verify_16(string1, string2):
    """
    Compares the first crypto_verify_16_BYTES of the given strings

    The time taken by the function is independent of the contents of string1
    and string2. In contrast, the standard C comparison function
    memcmp(string1,string2,16) takes time that is dependent on the longest
    matching prefix of string1 and string2. This often allows for easy
    timing attacks.
    """
    a, b, c = (
        (len(string1) >= 16),
        (len(string2) >= 16),
        (not nacl.crypto_verify_16(string1, string2)),
    )
    return a & b & c


def crypto_verify_32(string1, string2):
    """
    Compares the first crypto_verify_32_BYTES of the given strings

    The time taken by the function is independent of the contents of string1
    and string2. In contrast, the standard C comparison function
    memcmp(string1,string2,32) takes time that is dependent on the longest
    matching prefix of string1 and string2. This often allows for easy
    timing attacks.
    """
    a, b, c = (
        (len(string1) >= 32),
        (len(string2) >= 32),
        (not nacl.crypto_verify_32(string1, string2)),
    )
    return a & b & c


def crypto_verify_64(string1, string2):
    """
    Compares the first crypto_verify_64_BYTES of the given strings

    The time taken by the function is independent of the contents of string1
    and string2. In contrast, the standard C comparison function
    memcmp(string1,string2,64) takes time that is dependent on the longest
    matching prefix of string1 and string2. This often allows for easy
    timing attacks.
    """
    a, b, c = (
        (len(string1) >= 64),
        (len(string2) >= 64),
        (not nacl.crypto_verify_64(string1, string2)),
    )
    return a & b & c


def bytes_eq(a, b):
    """
    Compares two byte instances with one another. If `a` and `b` have
    different lengths, return `False` immediately. Otherwise `a` and `b`
    will be compared in constant time.

    Return `True` in case `a` and `b` are equal. Otherwise `False`.

    Raises :exc:`TypeError` in case `a` and `b` are not both of the type
    :class:`bytes`.
    """
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        raise TypeError("Both arguments must be bytes.")

    len_a = len(a)
    len_b = len(b)
    if len_a != len_b:
        return False

    return nacl.sodium_memcmp(a, b, len_a) == 0
