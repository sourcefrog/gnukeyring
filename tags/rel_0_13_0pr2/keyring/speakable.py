#! /usr/bin/python

import random

consonants = ['qu', 'w', 'r',
              't', 'th', 'tr', 
              'y',
              'p', 'pr', 'pl',
              's', 'sh', 'st', 'd', 'f', 'g',
              'h', 'j', 'k', 'l', 'z', 'x', 'c',
              'ch', 'cl', 'cr', 'v', 'b', 'n', 'm']
vowels = ['a', 'e', 'i', 'o', 'u']

for i in range(100):
    s = ''
    for j in range(4):
        for k in range(random.choice([1, 2, 2, 3])):
            s = s + random.choice(consonants) + random.choice(vowels)
        s = s + ' '
    print s
    
