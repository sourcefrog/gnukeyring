#!/usr/bin/perl
print <<EOF;
#
# Keyring -- store passwords securely on a handheld
# Copyright (C) 2003 Jochen Hoenicke <hoenicke@users.sourceforge.net>
#
# $Id$
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

#
# This is a hand optimized of SHA1.  This assembler code is autogenerated
# by a perl script.  Always change the Perl script.
#
EOF

$SECTION=".text";
open SECTIONS_H, "<sections.h";
while (<SECTIONS_H>) {
    if (/\#define\s+SHA1_SECTION\s+__attribute__\s*
	\(\(section\s*\("(.*)"\)\)\)/x) {
	$SECTION = qq(.section\t$1,"x");
	last;
    }
}
close SECTIONS_H;

print <<EOF;

	.file	"sha1-m68k.s"

$SECTION
	.even
.globl SHA1_Block
SHA1_Block:

	link.w %a6,\#-56
	movm.l \#0x1f38,-(%sp)
	move.l 8(%a6),%a0
        movm.l (%a0), \#0x001f
	move.l 12(%a6),%a0
EOF

#  Register use:
#    %d0-%d4:  A,B,C,D,E    (cycling)
#    %d5    :  T  (used for calculating F1-F4)
#    %d6,%d7:  cache some W[i] values, namely W[i-15] W[i-16].
#    %a0    :  address of buffer[i] if i < 16; address of W[i-14] otherwise
#    %a1-%a3:  cache some W[i] values, namely W[i-15] W[i-16].
#    %a4    :  current K value.
#    %a5-%a7:  reserved: GOT, FP, SP

$A='%d0';
$B='%d1';
$C='%d2';
$D='%d3';
$E='%d4';
$T='%d5';

$K='%a4';

@CACHE1 = ('%a1','%a2', '%a3');
@CACHE2 = ('%d6', '%d7');

@K=(0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6);

$WAITSTATES = 4;



my $cycles = 16 + 8 + 8*8 + 7*16;
$cycles += (4 + 18 + 4+4+3+16) * $WAITSTATES;

# Normally SHA1 first transforms the 16 word (64 byte) buffer
# into an 80 word buffer with
#    W[i] = buffer[i]                                       i <  16
#         = ROTATE(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16],1)   i >= 16
#
# We calculate W[i] on the fly, and store the last 14 words on the
# stack (in a cyclic buffer) from  -56(%a6) to -4(%a6) (inclusive)


# Return the address of W[i-8].
sub W8($) {
    my ($i) = @_;
    my $j;

    if (($i - 8) < 16) {
	# a0 = &W[i-14]
	$j = (14 - 8) * 4;
	return "$j(%a0)";
    } else {
	# We have to calculate address of W[i-8] relative to stack.
        # W[i] = &stack-56[($i-16) % 14]
	$j = -56 + 4*(($i-8-16) % 14);
	return "$j(%a6)";
    }
}
sub W14($) {
    # %a0 points to W[i-14]
    # We just have to determine whether to increase %a0
    my ($i) = @_;
    if ($i >= 30 && $i < 80 - 8) {
	# In this case %a0 is increased when storing W[i] (see function W0)
	return "(%a0)";
    } else {
	return "(%a0)+";
    }
}
sub W0($) {
    my ($i) = @_;
    if ($i < 30) {
	# We have to calculate address of W[i] relative to stack.
        # W[i] = &stack-56[($i-16) % 14]
	$j = -56 + (($i-16) %14) * 4;
	return "$j(%a6)";
    } else {
	# In this case %a0 = &W[i-14] = &W[i]
	return "(%a0)+";
    }
}

# Calculate Fi(B,C,D)  (result in T)
sub FUNC($$$$$) {
    my ($i,$B,$C,$D, $T) = @_;
    if ($i < 20) {
	# F1 = (B & C) | (~B & D) = ((D ^ C) & B) ^ D
	$cycles += 4 + 8 + 8 + 8 + 4*$WAITSTATES;
	print "\tmove.l $D, $T\n";
	print "\teor.l  $C, $T\n";
	print "\tand.l  $B, $T\n";
	print "\teor.l  $D, $T\n";
    } elsif ($i < 40) {
	# F2 = (B ^ C ^ D)
	$cycles += 4 + 8 + 8 + 3*$WAITSTATES;
	print "\tmove.l $D, $T\n";
	print "\teor.l  $C, $T\n";
	print "\teor.l  $B, $T\n";
    } elsif ($i < 60) {
	# F3 = ((B & C) | (B & D) | (C & D)) = ((B^C) & (B^D)) ^ B
	$cycles += 8 + 4 + 8 + 8 + 8 + 8 + 6*$WAITSTATES;
	print "\teor.l  $B, $D\n";    # modifies D
	print "\tmove.l $C, $T\n";
	print "\teor.l  $B, $T\n";
	print "\tand.l  $D, $T\n";
	print "\teor.l  $B, $D\n";    # restores D
	print "\teor.l  $B, $T\n";
    } else {
	# F4 = (B ^ C ^ D)
	$cycles += 4 + 8 + 8 + 3*$WAITSTATES;
	print "\tmove.l $D, $T\n";
	print "\teor.l  $C, $T\n";
	print "\teor.l  $B, $T\n";
    }
}


for ($i = 0; $i < 80; $i++) {
    my $tmp;
    print "\n\t\# Round $i cycles: $cycles\n";
    print "\t\# A=$A B=$B C=$C D=$D E=$E\n";
    
    print "\tmove.l \#$K[$i/20], $K\n" if (($i % 20) == 0);
    $cycles += 12  if (($i % 20) == 0);
    
    print "\tlea.l  -56(%a0), %a0\n" if ($i == 16);
    print "\tlea.l  -56(%a6), %a0\n" if ($i >= 30 && (($i-30) % 14) == 0);
    
    if ($i >= 16) {
	# Calculate W[i].  W[i] = ROTATE(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16],1)
	# CACHE2[0..1]  caches W[i-16..i-15]
	print "\t\# W[".($i-16)."]=$CACHE2[0] W[".($i-15)."]=$CACHE2[1]";
	# CACHE1[0..2]  caches W[i-3..i-1]
	print " W[".($i-3)."]=$CACHE1[0] W[".($i-2)."]=$CACHE1[1]".
	    " W[".($i-1)."]=$CACHE1[2]\n";
	print "\t# %a0 = &W[".($i-14)."]\n";

	my $W2 = $CACHE2[0];
	print "\tmove.l $CACHE1[0], $T\n";   #W = W[i-3]
	print "\teor.l  $W2, $T\n";          #  ^ W[i-16]
	print "\tmove.l ".W8($i).", $W2\n";
	print "\teor.l  $W2, $T\n";          #  ^ W[i-8]
	print "\tmove.l ".W14($i).", $W2\n";  #      (update cache2)
	print "\teor.l  $W2, $T\n";          #  ^ W[i-14]
	print "\trol.l  \#1, $T\n";
	# Note that CACHE2[0] now contains W[i-14]
	#       and CACHE1[0] now contains W[i]
	
        # store new value of W[i] in cyclic buffer (only if it is needed).
	print "\tmove.l $T, ". W0($i)."\n" if ($i < 80-8);
	print "\tmove.l $T, $CACHE1[0]\n"  if ($i < 80-3);
	print "\tadd.l  $T, $E\n";
	$cycles += 16 + 16 + 8 + 16 + 8 + 16 + 8 + 10 + 8;
	$cycles += 22 * $WAITSTATES;
	$cycles += 16 + 4*$WAITSTATES if ($i < 80-3);
	
	# cycle cache registers
	$tmp = $CACHE1[0];
	$CACHE1[0] = $CACHE1[1];
	$CACHE1[1] = $CACHE1[2];
	$CACHE1[2] = $tmp;
	
	$tmp = $CACHE2[0];
	$CACHE2[0] = $CACHE2[1];
	$CACHE2[1] = $tmp;
    } else {
	# take W[i] from (%a0) ;  but cache it if we need it later.
	if ($i < 2 || $i >= 13) {
	    $reg = $i < 2 ? $CACHE2[$i] : $CACHE1[$i-13];
	    if ($i >= 13) {
		# this instruction is slightly faster
		print "\tmovm.l  (%a0)+, \#0x0e00\n" if ($i == 13);
	    } else {
		print "\tmove.l  (%a0)+, $reg\n";
	    }
	    print "\tadd.l  $reg, $E\n";
	    $cycles += 16 + 4*$WAITSTATES + 8 + 1*$WAITSTATE;
	} else {
	    print "\tadd.l  (%a0)+, $E\n";
	    $cycles += 18 + 4*$WAITSTATES;
	}
    }

    FUNC($i, $B, $C, $D, $T);
    print "\tadd.l  $T, $E\n";
    
    print "\tadd.l  $K, $E\n";
    print "\tmove.l $A, $T\n";
    print "\trol.l  \#5, $T\n";
    print "\tadd.l  $T, $E\n";
    
    print "\tror.l  \#2, $B\n";
    $cycles += 8 + 8 + 4 + 18 + 8 + 12 + 8*$WAITSTATES;

    $tmp = $E;
    $E = $D;
    $D = $C;
    $C = $B;
    $B = $A;
    $A = $tmp;
}	

print "\n\t\# Finishing.  Cycles: $cycles\n";

print <<EOF;
	move.l 8(%a6),%a0
	move.l 16(%a6),%a1
	add.l (%a0)+,$A
	move.l $A,(%a1)+
	add.l (%a0)+,$B
	move.l $B,(%a1)+
	add.l (%a0)+,$C
	move.l $C,(%a1)+
	add.l (%a0)+,$D
	move.l $D,(%a1)+
	add.l (%a0),$E
	move.l $E,(%a1)
	movm.l (%sp)+,\#0x1cf8
	unlk %a6
	rts
	.byte 0x8a
	.ascii "SHA1_Block"
	.even
	.word 0
EOF

$cycles += 16 + 5*(16+12) + 12 + 8*8 + 12 + 16;
$cycles += (4 + 5*6 + 18 + 1 + 1) * $WAITSTATES;
print "\n\t\# Total cycles: $cycles\n";