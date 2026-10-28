"""Password hygiene for local accounts: the passwords that are tried first by every attacker are refused, as are a password that is the user name or a trivial pattern.

The list is the few hundred passwords that top every leaked-password ranking (all lower case: the check ignores case). It is not a full breached-password check (that needs
a large list or an outside service); it takes away the cheapest guesses, which is where credential-stuffing and brute-force start.
"""

from __future__ import annotations

import re

COMMON = frozenset("""
password password1 password12 password123 password1234 passw0rd p@ssw0rd p@ssword pa$$w0rd 123456 1234567 12345678 123456789 1234567890 12345678910 0123456789 111111 1111111 11111111
000000 00000000 123123 123123123 1q2w3e4r 1q2w3e4r5t 1qaz2wsx 1qazxsw2 qwerty qwerty1 qwerty12 qwerty123 qwertyuiop qwertyui qazwsx qazwsxedc zxcvbnm asdfghjkl asdfgh asdfg
letmein letmein1 welcome welcome1 welcome123 admin admin1 admin12 admin123 admin1234 administrator root toor changeme changeme123 default secret secret123 login master
abc123 abc12345 abcd1234 abcdefg abcdefgh abcdefgh1 iloveyou iloveyou1 monkey dragon baseball football soccer hockey batman superman trustno1 sunshine princess shadow michael
jennifer jordan hunter ranger buster thomas robert freedom whatever starwars pokemon hello hello123 helloworld test test123 test1234 testing testing123 guest guest123 user user123
netlens netlens1 netlens123 netlens! monitoring monitor network network1 server server123 raspberry raspberrypi pi ubuntu debian linux windows windows1 passwd pass pass123 pass1234
qwerty1234 qwerty12345 1234qwer 1234abcd a1b2c3d4 q1w2e3r4 q1w2e3 zaq12wsx zaq1zaq1 654321 7654321 87654321 987654321 9876543210 112233 11223344 121212 696969 12341234 123321
123qwe 123qweasd 123abc 12qwaszx 1g2w3e4r aaaaaa aaaaaaaa aaaa1111 qqqqqqqq zzzzzzzz mypassword mypassword1 mypass password! password. passw0rd1 letmein123 trustno1 starwars1
football1 baseball1 basketball superman1 batman123 iloveyou123 sunshine1 princess1 charlie liverpool chelsea arsenal manchester barcelona ashley nicole daniel jessica lovely
""".split())


class WeakPassword(ValueError):
    """A sentence the user can act on."""


def check(password: str, username: str = "") -> None:
    p = password or ""
    low = p.lower()
    if low in COMMON or re.sub(r"[^a-z0-9]", "", low) in COMMON:
        raise WeakPassword("that password is one of the most used passwords there are; choose another (a few unrelated words is a good choice)")
    if username and low == username.strip().lower():
        raise WeakPassword("the password must not be the user name")
    if len(set(p)) <= 2 and len(p) >= 6:
        raise WeakPassword("the password is only one or two different characters")
    digits = re.sub(r"\D", "", p)
    if p.isdigit() and (digits in "01234567890123456789" or digits in "98765432109876543210"):
        raise WeakPassword("the password is a run of digits")
