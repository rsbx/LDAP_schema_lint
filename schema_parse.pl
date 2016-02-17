#!/usr/bin/perl

#  Copyright (c) 2013-2016, Raymond S Brand
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#   * Redistributions in source or binary form must carry prominent
#     notices of any modifications.
#
#   * Neither the name of Raymond S Brand nor the names of its other
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
#  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
#  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
#  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
#  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.


use 5.10.1;
use strict;
use warnings;


# Settings
my $RelaxedTypeOid = 0;


# Constants
my $RE_numoid = '(?:(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+)';
my $RE_keystring = '(?:[A-Za-z][A-Za-z0-9-]*)';
my $RE_nameoid = "(?:$RE_numoid|$RE_keystring)";
my $RE_dstring = "(?:(?:\\\\27|\\\\5c|\\\\5C|[^'\\\\])+)";

my $RE_typeoid = $RelaxedTypeOid ? $RE_nameoid : $RE_numoid;


# State
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


sub ParseOid
	{
	my $oidstr = shift;
	my $rest;

	if ($oidstr =~ /^\s*($RE_nameoid)(\s.*$|$)/)
		{
		return ($2, $1);
		}

	return undef;
	}


sub ParseOids
	{
	my $oidstr = shift;

	my @oids = ();
	my $rest;

	if ($oidstr =~ /^\s*\(\s*($RE_nameoid(?:\s*\$\s*$RE_nameoid)*)\s*\)(\s.*$|$)/)
		{
		my $oids = $1;
		$rest = $2;

		$oids =~ s/\$/ /g;

		while ($oids !~ /^\s*$/)
			{
			my $oid;
			($oid, $oids) = $oids =~ /^\s*(\S+)(\s.*$|$)/;
			push @oids, $oid;
			}
		}
	elsif ($oidstr =~ /\s*($RE_nameoid)(\s.*$|$)/)
		{
		$rest = $2;
		push @oids, $1;
		}
	else
		{
		return undef;
		}

	return ($rest, \@oids);
	}


sub ParseQdescrs
	{
	my $qdescrstr = shift;

	my @qdescrs = ();
	my $rest;

	if ($qdescrstr =~ /^\s*\(\s*('[A-Za-z][A-Za-z0-9-]*'(\s+'[A-Za-z][A-Za-z0-9-]*')*)\s*\)(\s.*$|$)/)
		{
		my $descr;
		my $qdescrlist = $1;
		$rest = $3;

		while ($qdescrlist !~ /^\s*$/)
			{
			($descr, $qdescrlist) = $qdescrlist =~ /^\s*'([^']+)'(.*$)/;
			push @qdescrs, $descr;
			}
		}
	elsif ($qdescrstr =~ /^\s*'([A-Za-z][A-Za-z0-9-]*)'(\s.*$|$)/)
		{
		$rest = $2;
		push @qdescrs, $1;
		}
	else
		{
		return undef;
		}

	return ($rest, \@qdescrs);
	}


sub ParseQdstrings
	{
	my $qdstringsstr = shift;

	my @qdstrings = ();
	my $rest;

	if ($qdstringsstr =~ /^\s*\(\s*('(\\27|\\5c|\\5C|[^'\\])+'(\s+'(\\27|\\5c|\\5C|[^'\\])+')*)\s*\)(\s.*$|$)/)
		{
		my $dstring;
		my $qdstringlist = $1;
		$rest = $5;

		while ($qdstringlist !~ /^\s*$/)
			{
			($dstring, undef, $qdstringlist) = $qdstringlist =~ /^\s*'((\\27|\\5c|\\5C|[^'\\])+)'(.*$)/;
			push @qdstrings, $dstring;
			}
		}
	elsif ($qdstringsstr =~ /^\s*'(\\27|\\5c|\\5C|[^'\\])+'(\s.*$|$)/)
		{
		$rest = $2;
		push @qdstrings, $1;
		}
	else
		{
		return undef;
		}

	return ($rest, \@qdstrings);
	}


#######################################


sub Parse_EBNF_extensions
	{
	my ($obj, $string) = @_;

	$obj->{'X-'} = {};

	while ($string =~ /^\s+X-([A-Za-z_-]+)\s+(\S.*)$/)
		{
		my $key = $1;
		$string = $2;
		my $val;

		if (exists($obj->{'X-'}->{$key}))
			{
			return undef;
			}

		if (!scalar(($string, $val) = Parse_EBNF_qdstrings($string)))
			{
			return undef;
			}

		$obj->{'X-'}->{$key} = $val;
		}

	return $string;
	}


sub Parse_EBNF_noidlen
	{
	my $string = shift;

	if ($string !~ /^\s*($RE_numoid)((?:\{(?:0|[1-9][0-9]*)\})?(?:\s.*$|$))/)
		{
		return undef;
		}

	my $oid = [$1];
	$string = $2;

	if ($string =~ /^\{(0|[1-9][0-9]*)\}(\s.*$|$)/)
		{
		push @$oid, $1;
		$string = $2;
		}

	return ($string, $oid);
	}


sub Parse_EBNF_oid
	{
	my $string = shift;

	if ($string !~ /^\s*($RE_nameoid)(\s.*$|$)/)
		{
		return undef;
		}

	return ($2, [$1]);
	}


sub Parse_EBNF_qdescrs
	{
	my $string = shift;

	my @qdescrs = ();
	my $rest;

	if ($string =~ /^\s*\(\s*('$RE_keystring'(\s+'$RE_keystring')*)\s*\)(\s.*$|$)/)
		{
		my $descr;
		my $qdescrlist = $1;
		$rest = $3;

		while ($qdescrlist !~ /^\s*$/)
			{
			($descr, $qdescrlist) = $qdescrlist =~ /^\s*'($RE_keystring)'(.*$)/;
			push @qdescrs, $descr;
			}
		}
	elsif ($string =~ /^\s*'($RE_keystring)'(\s.*$|$)/)
		{
		$rest = $2;
		push @qdescrs, $1;
		}
	else
		{
		return undef;
		}

	return ($rest, \@qdescrs);
	}


sub Parse_EBNF_qdstring
	{
	my $string = shift;

	if ($string !~ /^\s*'($RE_dstring)'(\s.*$|$)/)
		{
		return undef;
		}
	my ($dstring, $rest) = ($1, $2);

	$dstring =~ s/\\27/\'/g;
	$dstring =~ s/\\5c|\\5C/\\/g;

	return ($rest, $dstring);
	}


sub Parse_EBNF_qdstrings
	{
	my $string = shift;

	my @qdstrings = ();
	my $rest;

	if ($string =~ /^\s*\(\s*('$RE_dstring'(?:\s+'$RE_dstring')*)\s*\)(\s.*$|$)/)
		{
		my $dstring;
		my $qdstringlist = $1;
		$rest = $2;

		while ($qdstringlist !~ /^\s*$/)
			{
			($dstring, $qdstringlist) = $qdstringlist =~ /^\s*'($RE_dstring)'(.*$)/;
			$dstring =~ s/\\27/\'/g;
			$dstring =~ s/\\5c|\\5C/\\/g;
			push @qdstrings, $dstring;
			}
		}
	elsif ($string =~ /^\s*'($RE_dstring)'(\s.*$|$)/)
		{
		my $dstring = $1;
		$rest = $2;
		$dstring =~ s/\\27/\'/g;
		$dstring =~ s/\\5c|\\5C/\\/g;
		push @qdstrings, $dstring;
		}
	else
		{
		return undef;
		}

	return ($rest, \@qdstrings);
	}


sub Parse_EBNF_usage
	{
	my $string = shift;

	if ($string !~ /^\s*(userApplications|directoryOperation|distributedOperation|dSAOperation)(\s.*$|$)/)
		{
		return undef;
		}

	return ($2, $1);
	}


sub Return_1
	{
	return ($_[0], 1);
	}


sub TableParse
	{
	my ($table, $obj, $string) = @_;

	for (my $i = 0; $i < scalar(@$table); $i++)
		{
		my ($field, $parser, $default, $key, $req) = @{$table->[$i]};

		$obj->{$key} = $default;

		if ($string =~ /^\s+$field(\s.*$|$)/)
			{
			my ($rest, $val);

			if (!scalar(($rest, $val) = &$parser($1)))
				{
				return undef;
				}

			$obj->{$key} = $val;
			$string = $rest;
			}
		}

	return $string;
	}


my $AttributeTypeDescription_ParseTable = [
		# Field				Parser			Default			Key			Req
		['NAME',			\&Parse_EBNF_qdescrs,	[],			'NAME',			0,],
		['DESC',			\&Parse_EBNF_qdstring,	undef,			'DESC',			0,],
		['OBSOLETE',			\&Return_1,		0,			'OBSOLETE',		0,],
		['SUP',				\&Parse_EBNF_oid,	[],			'SUP',			0,],
		['EQUALITY',			\&Parse_EBNF_oid,	[],			'EQALITY',		0,],
		['ORDERING',			\&Parse_EBNF_oid,	[],			'ORDERING',		0,],
		['SUBSTR',			\&Parse_EBNF_oid,	[],			'SUBSTR',		0,],
		['SYNTAX',			\&Parse_EBNF_noidlen,	[],			'SYNTAX',		0,],
		['SINGLE-VALUE',		\&Return_1,		0,			'SINGLE-VALUE',		0,],
		['COLLECTIVE',			\&Return_1,		0,			'COLLECTIVE',		0,],
		['NO-USER-MODIFICATION',	\&Return_1,		0,			'NO-USER-MODIFICATION',	0,],
		['USAGE',			\&Parse_EBNF_usage,	'userApplications',	'USAGE',		0,],
		];

		
sub Parse_LDAP_AttributeTypeDescription
	{
	my $value = shift;

	if ($value !~ /^\(\s*($RE_typeoid)((?:\s+\S+)*)\s*\)\s*$/)
		{
		return undef;
		}

	my $attr = {
		'-Type'		=> 'AttributeTypeDescription',
		'OID'		=> $1,
		};
	$value = $2;

	if (!defined ($value = TableParse($AttributeTypeDescription_ParseTable, $attr, $value)))
		{
		return undef;
		}

	if (!defined ($value = Parse_EBNF_extensions($attr, $value)))
		{
		return undef;
		}

	if ($value !~ /^\s*$/)
		{
		return undef;
		}

	return $attr;
	}


sub ParseAttribute
	{
	my ($item, $file, $line, $aref) = @_;

	my ($oid, $body) = $item =~ /^attributetypes:\s*\(\s*($RE_nameoid)((\s+.*)?)\)\s*$/i;

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

		if ($key eq 'NAME' && scalar(ParseQdescrs($rest)))
			{
			my $namesref;
			($rest, $namesref) = ParseQdescrs($rest);
			$attr->{'NAME'} = $namesref;
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
		elsif ($key eq 'SUP' && scalar(ParseOid($rest)))
			{
			my $sup;
			($rest, $sup) = ParseOid($rest);
			$attr->{'SUP'} = [$sup];
			}
		elsif ($key eq 'EQUALITY' && scalar(ParseOid($rest)))
			{
			($rest, $attr->{'EQUALITY'}) = ParseOid($rest);
			}
		elsif ($key eq 'ORDERING' && scalar(ParseOid($rest)))
			{
			($rest, $attr->{'ORDERING'}) = ParseOid($rest);
			}
		elsif ($key eq 'SUBSTR' && scalar(ParseOid($rest)))
			{
			($rest, $attr->{'SUBSTR'}) = ParseOid($rest);
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
		elsif ($key =~ /^X-/ && scalar(ParseQdstrings($rest)))
			{
			my $extsref;
			($rest, $extsref) = ParseQdstrings($rest);
			$attr->{'X-'}->{$key} = $extsref;
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


sub ParseObjectClass
	{
	my ($item, $file, $line, $aref) = @_;

	my ($oid, $body) = $item =~ /^objectclasses:\s*\(\s*($RE_nameoid)((\s+.*)?)\)\s*$/i;

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

		if ($key eq 'NAME' && scalar(ParseQdescrs($rest)))
			{
			my $namesref;
			($rest, $namesref) = ParseQdescrs($rest);
			$objc->{'NAME'} = $namesref;
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
		elsif ($key eq 'SUP' && scalar(ParseOids($rest)))
			{
			my $oidref;
			($rest, $oidref) = ParseOids($rest);
			$objc->{'SUP'} = $oidref;
			}
		elsif ($key =~ /ABSTRACT|STRUCTURAL|AUXILIARY/)
			{
			$objc->{'KIND'} = $key;
			}
		elsif ($key eq 'MUST' && scalar(ParseOids($rest)))
			{
			my $oidref;
			($rest, $oidref) = ParseOids($rest);
			$objc->{'MUST'} = $oidref;
			}
		elsif ($key eq 'MAY' && scalar(ParseOids($rest)))
			{
			my $oidref;
			($rest, $oidref) = ParseOids($rest);
			$objc->{'MAY'} = $oidref;
			}
		elsif ($key =~ /^X-/ && scalar(ParseQdstrings($rest)))
			{
			my $extsref;
			($rest, $extsref) = ParseQdstrings($rest);
			$objc->{'X-'}->{$key} = $extsref;
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
		if ($item =~ /^attributetypes:\s*(\S.*)$/i)
			{
			my $obj;
			if (!defined($obj = Parse_LDAP_AttributeTypeDescription($1)))
				{
				say 'Attribute definition ignored due to parse error';
				say "\tLine $line of '$schemafile'";
				next;
				}
			$obj->{'-Defined'} = [$schemafile, $line];
			push @attrs, $obj;
#use Data::Dumper;
#say Dumper($obj);
			}
		elsif ($item =~ /^objectclasses:/i)
			{
			ParseObjectClass($item, $schemafile, $line, \@objcs);
			}
		else
			{
#			say $item;
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
				$item->{'-TC_supers'} = [sort keys %{{map { (lc($_) => undef) } @{$supers}, $item->{'OID'}}}];
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
		next if $item->{'OID'} =~ /^\d.*\d$/;
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
	EQUALITY	=>	[],	# optional: undef	# oid
	ORDERING	=>	[],	# optional: undef	# oid
	SUBSTR		=>	[],	# optional: undef	# oid
	SYNTAX		=>	[[]],	# optional: undef	# oid
	SINGLE-VALUE	=>	bool,	# optional: false
	COLLECTIVE	=>	bool,	# optional: false
	RO		=>	bool,	# optional: false
	USAGE		=>	$,	# optional: 'userApplications'
	Extensions	=>	{[]},	# optional: []		# hashrefs
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
	Extensions	=>	{[]},	# optional: []		# hashrefs
	-Defined	=>	[],	# schema file & line defined
	-Type		=>	'objectclass',

	-TC_supers	=>	[],	# oids from SUP chains
	-TC_schemas	=>	[],	# schema files transitive closure
	-TC_musts	=>	[],	# oids, transitive closure
	-TC_mays	=>	[],	# oids, transitive closure
	);


