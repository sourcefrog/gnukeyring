$current_file="";
$last_file="";
$verbose = 0;
if ($headername=="") {
    $headername="_PROTO_H_";
}

print "/* This file is automatically generated with \"make proto\". DO NOT EDIT */\n\n";
print "#ifndef $headername\n";
print "#define $headername\n";

sub parseDefinition($) {
    $_ = $_[0];
    $_ =~ s/\s+/ /g;
    $_ =~ s/^\s//;
    $_ =~ s/\=.*$//;
    $_ =~ s/\s$//;

    print STDERR "parseDef: $_\n" if $verbose;
    # skip static/extern/typedef or nonalphanumeric things
    return if /^(static |extern |typedef |[^a-zA-Z_])/;
    # skip simple struct/class definition
    return if /^(struct|class|enum) [a-zA-Z_]+$/;
    if (!/[a-zA-Z0-9_][^a-zA-Z0-9_]+[a-zA-Z_]/) {
	return;
    }
    if ($current_file ne $last_file) {
	print "\n/* The following definitions come from $current_file */\n\n";
	$last_file = $current_file;
    }
    print "extern $_;\n";
}

while ($ARGV[0] eq "-v") {
    shift @ARGV;
    $verbose++;
}
    
while (<>)
{
    if ($ARGV ne $current_file) {
	if ($bracelevel || $incomment || $instring || $inchar
	    || $inif || $inifactive || $definitions !~ /^\s*$/) {
	    print STDERR "Warning: Couldn't parse $current_file.\n";
	}
	$current_file = $ARGV;
	$bracelevel = 0;
	$incomment = 0;
	$instring = 0;
	$inchar = 0;
	$inif = 0;
	$inifactive = 0;
	$wasactive = ();
	$definition = "";
    }

    print STDERR "read:$instring$inchar$incomment:$_" if $verbose > 2;

    # Handle if directives:  We parse #ifndef and #if 1 nodes and handle
    # else and elif correctly.
    if ($_ =~ /^\#(el)?if/) {
	if (!$1) {
	    $inif++;
	}
	if ($inifactive + 1 == $inif
	    && $_ =~ /^\#(el)?if(ndef\s.*|\s+1)$/) {
	    $inifactive++;
	} elsif ($inifactive == $inif) {
	    $inifactive--;
	    $wasactive[$inif] = 1;
	}
    } elsif ($_ =~ /^\#else/) {
	if ($inifactive + 1 == $inif && !$wasactive[$inif]) {
	    $inifactive++;
	} elsif ($inifactive == $inif) {
	    $inifactive--;
	    $wasactive[$inif] = 1;
	}
    } elsif ($_ =~ /^\#endif/) {
	if ($inifactive == $inif) {
	    $inifactive--;
	}
	$wasactive[$inif] = 0;
	$inif--;
    }

    next if $inifactive < $inif;

    if ($_ =~ /^\#/)  {
	# skip directives
	$_ = <> while ($_ =~ /\\$/);
	next;
    }

    while ($_) {
	if ($incomment) {
	    if ($_ =~ s/^([^\*]|\*+[^\*\/])*\*+\///) {
		$incomment = 0;
	    } else {
		last;
	    }
	}

	if ($instring) {
	    if ($_ =~ s/^(([^\\\"]|\\.)*\")//) {
		$definition .= "$1 " if (!$bracelevel);
		$instring = 0;
	    } else {
		$definition .= "$_" if (!$bracelevel);
		last;
	    }
	}

	if ($inchar) {
	    if ($_ =~ s/^(([^\\\']|\\.)*\')//) {
		$definition .= "$1" if (!$bracelevel);
		$inchar = 0;
	    } else {
		$definition .= "$_" if (!$bracelevel);
		last;
	    }
	}
    
	$_ =~ s/^(([^\{\}\"\'\;\/]|\/[^\/\*])*)//;
	if (!$bracelevel) {
	    $definition .= "$1 ";
	}

	if ($verbose > 1) {
	    $foo = $1;
	    if ($foo !~ /^\s*$/) {
		$foo =~ s/\n//g;
		print STDERR "$bracelevel:$foo:\n";
	    }
	}

	if ($_ =~ s/^\{//) {
	    if (!$bracelevel && $definition =~ /\(.*\)/s) {
		$tmp = $_;
		parseDefinition($definition);
		$_ = $tmp;
		$definition = "";
	    }
	    $bracelevel++;
	} elsif ($_ =~ s/^\}//) {
	    $bracelevel--;
	} elsif ($_ =~ s/^\/\*//) {
	    $incomment = 1;
	} elsif ($_ =~ s/^(\")//) {
	    $instring = 1;
	    $definition .= "$1" if (!$bracelevel);
	} elsif ($_ =~ s/^(\')//) {
	    $inchar = 1;
	    $definition .= "$1" if (!$bracelevel);
	} elsif ($_ =~ s/^\/\///) {
	    last;
	} elsif ($_ =~ s/^;//) {
	    if (!$bracelevel) {
		$tmp = $_;
		parseDefinition($definition);
		$_ = $tmp;
		$definition = "";
	    }
	}
    }
}

print "\n#endif /* _PROTO_H_ */\n";
