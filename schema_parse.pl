#!/usr/bin/perl

use 5.10.1;
use strict;
use warnings;


my $unwrap_state = undef;
my $unwrap_state_line = 0;
my $unwrap_curr_line = 0;
my $unwrap_fh = '';

sub unwrap
	{
	my $th = shift;

	if ($th ne $unwrap_fh)
		{
		if (defined $unwrap_state)
			{
			my $r = $unwrap_state;
			$unwrap_state = undef;
			return ($r, $unwrap_state_line);
			}

		$unwrap_fh = $th;
		$unwrap_curr_line = 0;
		}

	while (<$th>)
		{
		chomp;
		$unwrap_curr_line++;
		next if $_ =~ /^\s*#/;
		next if $_ =~ /^\s*$/;

		if ($_ !~ /^ / && defined $unwrap_state)
			{
			my ($r, $l) = ($unwrap_state, $unwrap_state_line);
			($unwrap_state, $unwrap_state_line) =
					($_, $unwrap_curr_line);
			return ($r, $l);
			}

		if ($_ !~ /^ /)
			{
			$unwrap_state = $_;
			$unwrap_state_line = $unwrap_curr_line;
			}
		else
			{
			$unwrap_state .= substr($_, 1);
			}
		}

	my ($r, $l) = ($unwrap_state, $unwrap_state_line);
	$unwrap_state = undef;
	$unwrap_state_line = 0;
	return ($r, $l);
	}


sub ParseAttribute
	{
	my ($item, $file, $line, $aref) = @_;

	my ($oid, $body) = $item =~ /^attributetypes:\s*\(\s*(\S+)((\s+.*)?)\)\s*$/i;

	my $attr = {
		'OID'		=> $oid,
		'NAME'		=> [],
		'OBSOLETE'	=> 0,
		'SINGLE-VALUE'	=> 0,
		'COLLECTIVE'	=> 0,
		'RO'		=> 0,
		'USAGE'		=> 'userApplications',
		'X-'		=> {},
		'-Defined'	=> [$file, $line],
		'-Type'		=> 'attribute',
		};

	while ($body !~ /^\s*$/)
		{
		my ($key, $rest) = $body =~ /^\s*(\S+)(\s.*$|$)/;
		if ($key eq 'NAME')
			{
			my @names = ();
			if ($rest =~ /^\s*\(/)
				{
				my $names;
				($names, $rest) = $rest =~ /^\s*\(([^)]*)\)(.*)$/;
				while ($names !~ /^\s*$/)
					{
					my $name;
					($name, $names) = $names =~ /^\s*'([^']*)'(.*)$/;
					push @{$attr->{'NAME'}}, $name;
					}
				}
			else
				{
				my $name;
				($name, $rest) = $rest =~ /^\s*'([^']*)'(.*)$/;
				push @{$attr->{'NAME'}}, $name;
				}
			}
		elsif ($key eq 'DESC')
			{
			my $desc;
			($desc, $rest) = $rest =~ /^\s*'([^']*)'(.*)$/;
			$attr->{'DESC'} = $desc;
			}
		elsif ($key eq 'OBSOLETE')
			{
			$attr->{'OBSOLETE'} = 1;
			}
		elsif ($key eq 'SUP')
			{
			my $sup;
			($sup, $rest) = $rest =~ /^\s*(\S+)(\s.*$|$)/;
			$attr->{'SUP'} = [$sup];
			}
		elsif ($key eq 'EQUALITY')
			{
			my $equality;
			($equality, $rest) = $rest =~ /^\s*(\S+)(\s.*$|$)/;
			$attr->{'EQUALITY'} = $equality;
			}
		elsif ($key eq 'ORDERING')
			{
			my $ordering;
			($ordering, $rest) = $rest =~ /^\s*(\S+)(\s.*$|$)/;
			$attr->{'ORDERING'} = $ordering;
			}
		elsif ($key eq 'SUBSTR')
			{
			my $substr;
			($substr, $rest) = $rest =~ /^\s*(\S+)(\s.*$|$)/;
			$attr->{'SUBSTR'} = $substr;
			}
		elsif ($key eq 'SYNTAX')
			{
			my $syntax;
			($syntax, $rest) = $rest =~ /^\s*(\S+)(\s.*$|$)/;
			$attr->{''} = $syntax;
			}
		elsif ($key eq 'SINGLE-VALUE')
			{
			$attr->{'SINGLE-VALUE'} = 1;
			}
		elsif ($key eq 'COLLECTIVE')
			{
			$attr->{'COLLECTIVE'} = 1;
			}
		elsif ($key eq 'NO-USER-MODIFICATION')
			{
			$attr->{'RO'} = 1;
			}
		elsif ($key eq 'USAGE')
			{
			my $usage;
			($usage, $rest) = $rest =~ /^\s*(\S+)(\s.*$|$)/;
			$attr->{'USAGE'} = $usage;
			}
		elsif ($key =~ /^X-/)
			{
			my $val;
			($val, $rest) = $rest =~ /^\s*'([^']*)'(.*)$/;
			$attr->{'X-'}->{$key} = $val;
			}
		else
			{
			say 'Attribute definition ignored due to parse error';
			say "\tLine $line of '$file'";
			return;
			}
		$body = $rest;
		}

	push @{$aref}, $attr;
	}


sub ParseOids
	{
	my $oidstr = shift;

	my @oids = ();
	my $rest;

	if ($oidstr =~ /^\s*\(/)
		{
		my $oids;
		($oids, $rest) = $oidstr =~ /^\s*\(([^)]*)\)(.*)$/;
		$oids =~ s/\$/ /g;

		while ($oids !~ /^\s*$/)
			{
			my $oid;
			($oid, $oids) = $oids =~ /^\s*(\S+)(\s.*$|$)/;
			push @oids, $oid;
			}
		}
	else
		{
		my $oid;
		($oid, $rest) = $oidstr =~ /^\s*(\S+)(\s.*$|$)/;
		push @oids, $oid;
		}

	return ($rest, \@oids);
	}


sub ParseObjectClass
	{
	my ($item, $file, $line, $aref) = @_;

	my ($oid, $body) = $item =~ /^objectclasses:\s*\(\s*(\S+)((\s+.*)?)\)\s*$/i;

	my $objc = {
		'OID'		=> $oid,
		'NAME'		=> [],
		'OBSOLETE'	=> 0,
		'KIND'		=> 'STRUCTURAL',
		'MUST'		=> [],
		'MAY'		=> [],
		'X-'		=> {},
		'-Defined'	=> [$file, $line],
		'-Type'		=> 'objectclass',
		};

	while ($body !~ /^\s*$/)
		{
		my ($key, $rest) = $body =~ /^\s*(\S+)(\s.*$|$)/;
		if ($key eq 'NAME')
			{
			my @names = ();
			if ($rest =~ /^\s*\(/)
				{
				my $names;
				($names, $rest) = $rest =~ /^\s*\(([^)]*)\)(.*)$/;
				while ($names !~ /^\s*$/)
					{
					my $name;
					($name, $names) = $names =~ /^\s*'([^']*)'(.*)$/;
					push @{$objc->{'NAME'}}, $name;
					}
				}
			else
				{
				my $name;
				($name, $rest) = $rest =~ /^\s*'([^']*)'(.*)$/;
				push @{$objc->{'NAME'}}, $name;
				}
			}
		elsif ($key eq 'DESC')
			{
			my $desc;
			($desc, $rest) = $rest =~ /^\s*'([^']*)'(.*)$/;
			$objc->{'DESC'} = $desc;
			}
		elsif ($key eq 'OBSOLETE')
			{
			$objc->{'OBSOLETE'} = 1;
			}
		elsif ($key eq 'SUP')
			{
			my $oidref;
			($rest, $oidref) = ParseOids($rest);
			$objc->{'SUP'} = $oidref;
			}
		elsif ($key =~ /ABSTRACT|STRUCTURAL|AUXILIARY/)
			{
			$objc->{'KIND'} = $key;
			}
		elsif ($key eq 'MUST')
			{
			my $oidref;
			($rest, $oidref) = ParseOids($rest);
			$objc->{'MUST'} = $oidref;
			}
		elsif ($key eq 'MAY')
			{
			my $oidref;
			($rest, $oidref) = ParseOids($rest);
			$objc->{'MAY'} = $oidref;
			}
		elsif ($key =~ /^X-/)
			{
			my $val;
			($val, $rest) = $rest =~ /^\s*'([^']*)'(.*)$/;
			$objc->{'X-'}->{$key} = $val;
			}
		else
			{
			say 'ObjectClass definition ignored due to parse error';
			say "\tLine $line of '$file'";
			return;
			}
		$body = $rest;
		}

	push @{$aref}, $objc;
	}


my @attrs = ();
my @objcs = ();

while (@ARGV)
	{
	my $schemafile = shift @ARGV;
	my ($item, $line);

	open(my $fh, '<', $schemafile) || next;
	while ((($item, $line) = unwrap($fh)) && $line)
		{
		if ($item =~ /^attributetypes:/i)
			{
			ParseAttribute($item, $schemafile, $line, \@attrs);
			}
		elsif ($item =~ /^objectclasses:/i)
			{
			ParseObjectClass($item, $schemafile, $line, \@objcs);
			}
		else
			{
			say $item;
			}
		}
	close($fh);
	}

say scalar(@attrs), ' attributes defined';
say scalar(@objcs), ' objectclasses defined';

my %oids = ();
my %names = ();

for my $item (@attrs, @objcs)
	{
	my $oid = $item->{'OID'};
	$oids{lc $oid} = [] if !defined $oids{lc $oid};
	push @{$oids{lc $oid}}, $item;

	for my $name (@{$item->{'NAME'}})
		{
		$names{lc $name} = [] if !defined $names{lc $name};
		push @{$names{lc $name}}, $item;
		}
	}

for my $oid (sort {$a cmp $b} keys %oids)
	{
	next unless exists $names{lc $oid};

	say "OID and Name conflict: '$oid'";
	}

for my $oid (sort {$a cmp $b} keys %oids)
	{
	next if @{$oids{$oid}} == 1;

	say "OID '$oid' defined multiple times:";
	for my $item (@{$oids{$oid}})
		{
		say "\t",$item->{'-Type'};
		say "\t\tLine ",$item->{'-Defined'}->[1]," of '",$item->{'-Defined'}->[0],"'";
		}
	}

for my $oid (sort {$a cmp $b} keys %oids)
	{
	next if @{$oids{$oid}} == 1;

	my $type = $oids{$oid}->[0]->{'-Type'};
	my $conflict = 0;
	for my $item (@{$oids{$oid}})
		{
		$conflict = 1 if $type ne $item->{'-Type'};
		}

	next unless $conflict;

	say "OID '$oid' defined with multiple types:";
	for my $item (@{$oids{$oid}})
		{
		say "\t",$item->{'-Type'};
		say "\t\tLine ",$item->{'-Defined'}->[1]," of '",$item->{'-Defined'}->[0],"'";
		}
	}

for my $name (sort {$a cmp $b} keys %names)
	{
	next if @{$names{$name}} == 1;

	say "NAME '$name' defined multiple times:";
	for my $item (@{$names{$name}})
		{
		say "\t",$item->{'-Type'};
		say "\t\tLine ",$item->{'-Defined'}->[1]," of '",$item->{'-Defined'}->[0],"'";
		}
	}

for my $name (sort {$a cmp $b} keys %names)
	{
	next if @{$names{$name}} == 1;

	my $type = $names{$name}->[0]->{'-Type'};
	my $conflict = 0;
	for my $item (@{$names{$name}})
		{
		$conflict = 1 if $type ne $item->{'-Type'};
		}
	next unless $conflict;

	say "NAME '$name' defined with multiple types:";
	for my $item (@{$names{$name}})
		{
		say "\t",$item->{'-Type'};
		say "\t\tLine ",$item->{'-Defined'}->[1]," of '",$item->{'-Defined'}->[0],"'";
		}
	}


#
# Inheritance loops
#


sub GetSupers
	{
	my ($aref, $type) = @_;
	my @supers = ();
	my @sups = ();

	for my $sup (@{$aref})
		{
		push @sups, @{$oids{lc $sup}} if exists $oids{lc $sup};
		push @sups, @{$names{lc $sup}} if exists $names{lc $sup};
		}

	for my $item (@sups)
		{
		next if lc($type) ne lc($item->{'-Type'});
		return undef unless exists $item->{'-TC_supers'};
		push @supers, @{$item->{'-TC_supers'}};
		}

	return \@supers;
	}


sub inheritance_loop
	{
	my ($aref, $type) = @_;

	my $progress;
	my @remain;
	my @items = @{$aref};

	do
		{
		$progress = 0;
		@remain = ();

		while (@items)
			{
			my $item = shift @items;
			if (!defined $item->{'SUP'})
				{
				$item->{'-TC_supers'} = [$item->{'OID'}];
				$progress = 1;
				}
	
			next if exists $item->{'-TC_supers'};
	
			my $supers = GetSupers($item->{'SUP'}, $type);
			if (defined $supers)
				{
				$item->{'-TC_supers'} = [sort keys {map { (lc($_) => undef) } @{$supers}, $item->{'OID'}}];
				$progress = 1;
				next;
				}
			push @remain, $item;
			}
	
		@items = @remain;
		} while $progress;

	return \@remain;
	}


my $remain = inheritance_loop(\@objcs, 'objectclass');
if (@{$remain})
	{
	say "Objectclass circular or missing SUP definitions";
	for my $item (@{$remain})
		{
		say "\t",$item->{'-Type'};
		say "\t\tLine ",$item->{'-Defined'}->[1]," of '",$item->{'-Defined'}->[0],"'";
		}
	}

$remain = inheritance_loop(\@attrs, 'attribute');
if (@{$remain})
	{
	say "Attribute circular or missing SUP definitions";
	for my $item (@{$remain})
		{
		say "\t",$item->{'-Type'};
		say "\t\tLine ",$item->{'-Defined'}->[1]," of '",$item->{'-Defined'}->[0],"'";
		}
	}





#for my $name (sort {$a cmp $b} keys %names)
#	{
#	say "NAME '$name' defined:";
#	for my $item (@{$names{$name}})
#		{
#		say "\t",$item->{'-Type'};
#		say "\t\tLine ",$item->{'-Defined'}->[1]," of '",$item->{'-Defined'}->[0],"'";
#		}
#	}

#for my $oid (sort {$a cmp $b} keys %oids)
#	{
#	say "OID '$oid' defined:";
#	for my $item (@{$oids{$oid}})
#		{
#		say "\t",$item->{'-Type'};
#		say "\t\tLine ",$item->{'-Defined'}->[1]," of '",$item->{'-Defined'}->[0],"'";
#		}
#	}


for my $name (sort {$a cmp $b} keys %names)
	{
	for my $item (@{$names{$name}})
		{
#		next if $item->{'OID'} =~ /^\d.*\d$/;
		say "'$name' ", $item->{'-Type'}, " ", ,$item->{'OID'};
		}
	}





__END__

attribute = (
	OID		=>	$,	# required
	NAME		=>	[],	# optional: []		# strings
	DESC		=>	$,	# optional: undef	# string
	OBSOLETE	=>	bool,	# optional: false
	SUP		=>	[],	# optional: undef	# oid
	EQUALITY	=>	$,	# optional: undef	# oid
	ORDERING	=>	$,	# optional: undef	# oid
	SUBSTR		=>	$,	# optional: undef	# oid
	SYNTAX		=>	$,	# optional: undef	# oid
	SINGLE-VALUE	=>	bool,	# optional: false
	COLLECTIVE	=>	bool,	# optional: false
	RO		=>	bool,	# optional: false
	USAGE		=>	$,	# optional: 'userApplications'
	Extensions	=>	[],	# optional: []		# hashrefs
	-Defined	=>	[],	# schema file & line defined
	-Type		=>	'attribute',

	-EQUALITY	=>	$,	# defined or inherited value
	-ORDERING	=>	$,	# defined or inherited value
	-SUBSTR		=>	$,	# defined or inherited value
	-SYNTAX		=>	$,	# defined or inherited value

	-TC_supers	=>	[],	# oids from SUP chain
	-TC_schemas	=>	[],	# schema files transitive closure
	);


objectclass = (
	OID		=>	$,	# required
	NAME		=>	[],	# optional: []		# strings
	DESC		=>	$,	# optional: undef
	OBSOLETE	=>	bool,	# optional: false
	SUP		=>	[],	# optional: []		# oids
	KIND		=>	$,	# optional: 'STRUCTURAL'
	MUST		=>	[],	# optional: []		# oids
	MAY		=>	[],	# optional: []		# oids
	Extensions	=>	[],	# optional: []		# hashrefs
	-Defined	=>	[],	# schema file & line defined
	-Type		=>	'objectclass',

	-TC_supers	=>	[],	# oids from SUP chains
	-TC_schemas	=>	[],	# schema files transitive closure
	-TC_musts	=>	[],	# oids, transitive closure
	-TC_mays	=>	[],	# oids, transitive closure
	);


