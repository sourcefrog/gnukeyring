#! /usr/bin/python

# $Id$

# Prototype of generating pronounceable passwords.  This one works OK
# - the passwords produced are pronounceable, but they do not look
# much like English.

# Maybe a Markov model constructed from actual
# text would be better?  We can't afford too large a table, though: if
# we use just 26 letters plus space, and map from the previous two
# characters to probabilities of the next, then we'd use 27**3 bytes =
# 20k, which is far too much for PalmOS.  There are 27**2 == 729
# precursor states, but many of them will be empty.

# Perhaps we should explicitly encode the states we've seen, and make
# sure they're fully connected?  Just store for each state a list of
# possible transitions out, and for each the character to emit, the
# probability, and the next state number.  I think then we could make
# the table any arbitrary length.

import random

consonants = [
              'b', 'bl',
              'c', 'ch', 'cl', 'cr',
              'd', 'dr',
              'f',
              'g', 'gr', 
              'h', 'j', 'k', 'l', 'm', 'n',
              'p', 'pr', 'pl',
              'qu', 'r',
              's', 'sh', 'sl', 'sp', 'spr', 'st', 'str', 'sm',
              't', 'th', 'tr', 'tw',
              'v', 'w', 'y', 'z' ]
vowels = ['a', 'e', 'i', 'o', 'u']

for i in range(100):
    s = ''
    for j in range(4):
        for k in range(random.choice([1, 2, 2, 3])):
            s = s + random.choice(consonants) + random.choice(vowels)
        s = s + ' '
    print s
    
