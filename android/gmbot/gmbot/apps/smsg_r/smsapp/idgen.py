import random
import cPickle

__cachefile = 'pygpw_tris_cache.cpickle'
_lowercase = 'abcdefghijklmnopqrstuvwxyz'
_uppercase = _lowercase.upper()
_vowels = 'aeiou'
_numbers = '0123456789'
_symbols = '`~!@#$%^&*()-=_+[]{}\\|;:\'",.<>/?'
_leet_table = {
    # lowercase: ([singlechar_substs],[multichar_substs])
    'a': (['4', '@', '^'], ['/\\', '/-\\']),
    'b': (['6', '8', '&'], ['|3', '13', 'I3']),
    'c': (['<', '(', '{'], []),
    'd': ([], ['|)', '])', '[)', 'I>', '|>']),
    'e': (['3', '&'], []),
    'f': ([], ['ph', '|=', ']=', 'I=']),
    'g': (('9', '6'), ['(_+']),
    'h': ([], ['/-/', ']-[', '|-|', '}{', '}-{']),
    'i': (('1', '|', '!'), []),
    'j': ([], ['_|', '_/', '_7']),
    'k': ([], ['|<', '|{']),
    'l': (['|'], ['|_', ]),
    'm': ([], ['/\\/\\', '|V|', '||', '[V]', '|\\/|', '/|\\', '/|/|', '/V\\']),
    'n': (['~'], ['|\\|', '/\\/', '|\\', ']\\[']),
    'o': (['0', ], ['()', '[]']),
    'p': (['?'], ['|*', '|o', '|>', '|D']),
    'q': (['9'], ['()_', 'O_', '0_', '<|']),
    'r': (['2'], ['12', '|?', '/2', '|~', '|2', '|`', 'l2']),
    's': (['5', '$', 'z'], []),
    't': (['+', '7'], ['-|-', ]),
    'u': ([], ['|_|', '[_]', '\_/', '\\_\\', '/_/', '(_)']),
    'v': ([], ['\\/']),
    'w': ([], ['\\/\\/', 'VV', '\\^/', '\\V/', '\\|/']),
    'x': (['%', '*'], ['><', '}{']),
    'y': ([], ['`/']),
    'z': (['2', 's'], ['7_']),
}
_tris = None
_sigma = None


def _docache():
    """
    (re)build cache using cPickle. This will be automatically called if the
    cachefile is not found, so you can recreate the cache by simply deleting
    the existing one
    """
    # load tris 
    # calculate the sigma value: the probability total of the trigraph set
    # sigma calculation result is cached, since source is relatively static.
    from smsapp.idgen_tris import tris

    sigma = 0
    for c1 in xrange(26):
        for c2 in xrange(26):
            for c3 in xrange(26):
                sigma += tris[c1][c2][c3]
                # tris cached since cPickle has superior I/O speed than .pyc marshalling
    dumpobj = (tris, sigma)  # dump tuple
    fhw = open(__cachefile, 'w')
    cPickle.dump(dumpobj, fhw)
    fhw.close()


def _readcache():
    """get the trigraph data from cachefile. returns a tuple (t,s) 
    where t is the matrix and s is the sigma value"""
    fh = None
    try:
        fh = open(__cachefile, 'r')
    except:
        # build if does not exist
        _docache()
        fh = open(__cachefile, 'r')
    cachedata = cPickle.load(fh)
    fh.close()
    return cachedata


def gettris():
    """get the trigraph probability matrix and sigma value. 
    returns a tuple (t,s) where t is the matrix and s is the sigma value."""
    global _tris
    global _sigma
    if not _tris or not _sigma:
        # store into module namespace so future calls require no I/O
        _tris, _sigma = _readcache()
    return _tris, _sigma


def generate_trigraph(passwordlength=8, alphabet=None, vowels=None):
    '''Generator'''
    _alphabet = _lowercase
    tdata, sigma = gettris()
    password = []  # append required

    # pick random starting point
    # we do it this way so we can be sure to pick a natural english
    # trigraph as a starting point, not just random gibberish, since
    # trigraphs with zero english occurrences are never chosen.
    ranno = int(sigma * random.random())
    sum = 0
    bail = False
    for c1 in xrange(26):
        for c2 in xrange(26):
            for c3 in xrange(26):
                sum += tdata[c1][c2][c3]
                if sum >= ranno:
                    # this is the starting random (but probable) trigraph
                    password.append(_alphabet[c1])
                    password.append(_alphabet[c2])
                    password.append(_alphabet[c3])
                    bail = True  # break out of this triply-nested loop
                if bail:
                    break
            if bail:
                break
        if bail:
            break

    # do random walk
    nchar = 3
    while nchar < passwordlength:
        c1 = _alphabet.find(password[nchar - 2])
        c2 = _alphabet.find(password[nchar - 1])

        # we have a password ...[c1][c2][?] character triplet
        # --------->|
        # (current password)
        # with c1 and c2 being the last two chars of current password. 
        # want to append another char (i.e. '?') to password.
        # randomly grab the third ('?') from trigraph table
        # using probability density defined in that data[c1][c2] list.
        sum = 0
        for c3 in xrange(26):
            sum += tdata[c1][c2][c3]

        if sum == 0:
            # in this unlikely case, we have a c1, c2 pair where there 
            # are zero natural trigraphs starting with [c1][c2]
            # meaning we cant continue any further.
            # For correctness, we should break the loop for
            # this password or try again. 
            # However, another workaround is to 'inject' a random vowel to
            # continue and finish the rest of this password.
            # --- Comment out either one of the 2 below lines ---
            # break
            password.extend(random.sample(_vowels, 1))
        else:
            ranno = int(random.random() * sum)
            sum = 0
            for c3 in xrange(26):
                sum += tdata[c1][c2][c3]
                if sum > ranno:
                    password.append(_alphabet[c3])
                    break
        nchar += 1
    # end random walk
    return ''.join(password)


def generate_naive(passwordlength=8, vowel_interlace=False, alphabet=_lowercase, vowels=_vowels):
    '''naive implementation. Set vowel_interlace=True to simulate pronouncable passwords'''
    pw = []
    for pos in xrange(passwordlength):
        # if vowel_interlace, dont allow two consonants in a row
        if vowel_interlace and pos > 0 and not pw[pos - 1] in _vowels:
            pw.extend(random.sample(vowels, 1))
        else:
            pw.extend(random.sample(alphabet, 1))
    return "".join(pw)


def leetify_string(plain, capitalize_rate=0.5, substitute_rate=0.5, multichar=False):
    leet = []
    c_idx = 0
    leet_len = 0
    maxchars = len(plain)
    while leet_len < len(plain):
        c = plain[c_idx]
        cl = c.lower()
        if leet_len == len(plain):
            break
        maxchars = len(plain) - leet_len
        if maxchars == 0:
            break
        if random.random() < capitalize_rate:
            if c == cl:
                c = c.upper()
            else:
                c = c.lower()
        if random.random() < substitute_rate:
            single_subs, multi_subs = _leet_table.get(cl, ([c], []))
            # try picking a multicharacter substitute that will fit it in
            if multichar and len(multi_subs) > 0:
                if maxchars == 1:
                    if len(single_subs) > 0:
                        c = random.sample(single_subs, 1)[0]
                    leet.append(c)
                    c_idx += 1
                    leet_len += len(c)
                    continue
                # temporary selection pool of mixed multi and single
                tmp_subs = []
                tmp_subs.extend(single_subs[:])
                tmp_subs.extend(multi_subs[:])
                tmp = None
                while len(tmp_subs):
                    tmp = random.sample(tmp_subs, 1)[0]
                    if len(tmp) > maxchars:
                        # remove this subst entry, it's too big
                        tmp_subs.remove(tmp)
                    else:
                        tmp_subs = []  # break inner loop
                if not tmp is None:
                    if len(tmp) <= maxchars:
                        c = tmp
            else:
                if len(single_subs) > 0:
                    c = random.sample(single_subs, 1)[0]
        leet.append(c)
        c_idx += 1
        leet_len += len(c)
    # return a output, explain pair
    return ''.join(leet), plain[:c_idx]


_methods = {
    # name, (func, default kwargs dict)
    'trigraph': (generate_trigraph, {}),
    'naive': (generate_naive, {'vowel_interlace': True}),
    'random': (generate_naive, {'vowel_interlace': False}),
}


def generate(numpasswords=1, passwordlength=8, method='trigraph', verbose=False,
             leetify=False, alphabet=_lowercase, vowels=_vowels,
             explain=False, multichar=False, substitute_rate=0.5, capitalize_rate=0.5):
    '''main generate loop'''
    gfunc, kwargs = _methods[method]
    passlist = []
    for i in xrange(numpasswords):
        pw = gfunc(passwordlength=passwordlength, alphabet=alphabet, vowels=vowels, **kwargs)
        pw_explain = pw
        if leetify:
            pw, pw_explain = leetify_string(pw, multichar=multichar,
                                            substitute_rate=substitute_rate,
                                            capitalize_rate=capitalize_rate)
        passlist.append(pw)
    return passlist


class __NP():
    @staticmethod
    def write(x):
        pass


def generate_uniq_id():
    """
    Generates friendly UUID
    @return UUID
    @rtype str
    """
    generate_args = {
        'numpasswords': 1,
        'passwordlength': 8,
        'leetify': False,
        'method': 'naive',
        'alphabet': _uppercase
    }
    p = generate(**generate_args)
    if p:
        return "{0:s}{1:02d}".format(p[0], random.randint(0, 99))
