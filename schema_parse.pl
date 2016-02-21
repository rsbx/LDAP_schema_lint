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
my $RelaxedTypeOid = 1;


# Constants
my $RE_numoid = '(?:(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+)';
my $RE_keystring = '(?:[A-Za-z][A-Za-z0-9-]*)';
my $RE_nameoid = "(?:$RE_numoid|$RE_keystring)";
my $RE_dstring = "(?:(?:\\\\27|\\\\5c|\\\\5C|[^'\\\\])+)";
my $RE_ruleid = '(?:0|[1-9][0-9]*)';

my $RE_typeoid = $RelaxedTypeOid ? $RE_nameoid : $RE_numoid;


# State
my %SchemaElements = ();
my %Oids = ();
my %Names = ();

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


#######################################


sub IsNumoid
	{
	my $oid = shift;

	return ($oid =~ /^$RE_numoid$/) ? 1 : 0;
	}


sub CmpOids
	{
	my ($oidA, $oidB) = @_;

	my $t;

	if ($t = IsNumoid($oidB) <=> IsNumoid($oidA))
		{
		return $t;
		}

	my @A = split('\.', $oidA);
	my @B = split('\.', $oidB);

	while (scalar(@A) && scalar(@B))
		{
		my $a = shift @A;
		my $b = shift @B;

		if ($t = ($b =~ /^[0-9]+/ <=> $a =~ /^[0-9]+/))
			{
			return $t;
			}

		if ($t = ($a =~ /^[0-9]+/) ? $a <=> $b : $a cmp $b)
			{
			return $t;
			}
		}

	return scalar(@A) <=> scalar(@B);
	}


#######################################


sub IsRuleID
	{
	my $ruleid = shift;

	return ($ruleid =~ /^$RE_ruleid$/) ? 1 : 0;
	}


#######################################


sub Parse_ABNF_extensions
	{
	my ($obj, $string) = @_;

	$obj->{'-X'} = {};

	while ($string =~ /^\s+X-([A-Za-z_-]+)\s+(\S.*)$/)
		{
		my $key = $1;
		$string = $2;
		my $val;

		if (exists($obj->{'-X'}->{$key}))
			{
			return ();
			}

		if (!scalar(($string, $val) = Parse_ABNF_qdstrings($string)))
			{
			return ();
			}

		$obj->{'-X'}->{$key} = $val;
		}

	return $string;
	}


sub Parse_ABNF_noidlen
	{
	my $string = shift;

	if ($string !~ /^\s*($RE_numoid)((?:\{(?:0|[1-9][0-9]*)\})?(?:\s.*$|$))/)
		{
		return ();
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


sub Parse_ABNF_numoid
	{
	my $string = shift;

	if ($string !~ /^\s*($RE_numoid)(\s.*$|$)/)
		{
		return ();
		}

	return ($2, [$1]);
	}


sub Parse_ABNF_oid
	{
	my $string = shift;

	if ($string !~ /^\s*($RE_nameoid)(\s.*$|$)/)
		{
		return ();
		}

	return ($2, [$1]);
	}


sub Parse_ABNF_oids
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
		return ();
		}

	return ($rest, \@oids);
	}


sub Parse_ABNF_qdescrs
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
		return ();
		}

	return ($rest, \@qdescrs);
	}


sub Parse_ABNF_qdstring
	{
	my $string = shift;

	if ($string !~ /^\s*'($RE_dstring)'(\s.*$|$)/)
		{
		return ();
		}
	my ($dstring, $rest) = ($1, $2);

	$dstring =~ s/\\27/\'/g;
	$dstring =~ s/\\5c|\\5C/\\/g;

	return ($rest, $dstring);
	}


sub Parse_ABNF_qdstrings
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
		return ();
		}

	return ($rest, \@qdstrings);
	}


sub Parse_ABNF_ruleids
	{
	my $ruleidstr = shift;

	my @ruleids = ();
	my $rest;

	if ($ruleidstr =~ /^\s*\(\s*($RE_ruleid(?:\s*$RE_ruleid)*)\s*\)(\s.*$|$)/)
		{
		my $ruleids = $1;
		$rest = $2;

		$ruleids =~ s/\$/ /g;

		while ($ruleids !~ /^\s*$/)
			{
			my $ruleid;
			($ruleid, $ruleids) = $ruleids =~ /^\s*(\S+)(\s.*$|$)/;
			push @ruleids, $ruleid;
			}
		}
	elsif ($ruleidstr =~ /\s*($RE_ruleid)(\s.*$|$)/)
		{
		$rest = $2;
		push @ruleids, $1;
		}
	else
		{
		return ();
		}

	return ($rest, \@ruleids);
	}


sub Parse_ABNF_usage
	{
	my $string = shift;

	if ($string !~ /^\s*(userApplications|directoryOperation|distributedOperation|dSAOperation)(\s.*$|$)/)
		{
		return ();
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


sub Parse_TypeOid
	{
	my ($obj, $field, $string) = @_;

	if ($string !~ /^\s*($RE_typeoid)((?:\s+\S+)*)\s*$/)
		{
		return undef;
		}

	$obj->{$field} = $1;

	return $2;
	}


sub Parse_RuleID
	{
	my ($obj, $field, $string) = @_;

	if ($string !~ /^\s*($RE_ruleid)((?:\s+\S+)*)\s*$/)
		{
		return undef;
		}

	$obj->{$field} = $1;

	return $2;
	}


sub Check_Isolated_ObjectClasses
	{
	my $obj = shift;

	my $count = $obj->{'-ABSTRACT'} + $obj->{'-STRUCTURAL'} + $obj->{'-AUXILIARY'};

	if ($count == 0)
		{
		$obj->{'-STRUCTURAL'} = 1;
		}
	elsif ($count != 1)
		{
		return undef;
		}

	return $obj;
	}


sub Check_Isolated_AttributeTypes
	{
	my $obj = shift;

	if (!scalar(@{$obj->{'SUP'}}) && !scalar(@{$obj->{'-SYNTAXLEN'}}))
		{
		return undef;
		}

	$obj->{'-DSYNTAX'} = [];
	$obj->{'-DLENMINMAX'} = undef;
	if (scalar(@{$obj->{'-SYNTAXLEN'}}))
		{
		$obj->{'-DSYNTAX'} = [$obj->{'-SYNTAXLEN'}->[0]];
		$obj->{'-DLENMINMAX'} = $obj->{'-SYNTAXLEN'}->[1];
		}

	return $obj;
	}


#######################################


sub Lookup_nameoid
	{
	my ($namespace, $nameoid) = @_;

	if (IsNumoid($nameoid))
		{
		return exists($Oids{$nameoid}) ? $Oids{$nameoid} : [];
		}
	else
		{
		return exists($SchemaElements{$namespace}->{'Names'}->{$nameoid}) ? $SchemaElements{$namespace}->{'Names'}->{$nameoid} : [];
		}
	}


sub Lookup_ruleid
	{
	my ($namespace, $ruleid) = @_;

	if (!IsRuleID($ruleid))
		{
		return [];
		}

	return exists($SchemaElements{$namespace}->{'RuleIds'}->{$ruleid}) ? $SchemaElements{$namespace}->{'RuleIds'}->{$ruleid} : [];
	}


#######################################


my %Table_LDAP_RFC4512_Schema_Type_Parse = (
		lc('objectClasses') => {
				'ParseElementID' => [\&Parse_TypeOid, '-OID'],
				'ParseTable' => [
						# Field				Parser			Default			Key			Req
						['NAME',			\&Parse_ABNF_qdescrs,	[],			'NAME',			0,],
						['DESC',			\&Parse_ABNF_qdstring,	undef,			'DESC',			0,],
						['OBSOLETE',			\&Return_1,		0,			'OBSOLETE',		0,],
						['SUP',				\&Parse_ABNF_oids,	[],			'SUP',			0,],
						['ABSTRACT',			\&Return_1,		0,			'-ABSTRACT',		0,],
						['STRUCTURAL',			\&Return_1,		0,			'-STRUCTURAL',		0,],
						['AUXILIARY',			\&Return_1,		0,			'-AUXILIARY',		0,],
						['MUST',			\&Parse_ABNF_oids,	[],			'MUST',			0,],
						['MAY',				\&Parse_ABNF_oids,	[],			'MAY',			0,],
						],
				'Check_Isolated' => \&Check_Isolated_ObjectClasses,
				'Check_ReferencedTypeTable' => [
						#Field				Lookup			Type
						['SUP',				\&Lookup_nameoid,	'objectClasses',	],
						['MUST',			\&Lookup_nameoid,	'attributeTypes',	],
						['MAY',				\&Lookup_nameoid,	'attributeTypes',	],
						],
				},
		lc('attributeTypes') => {
				'ParseElementID' => [\&Parse_TypeOid, '-OID'],
				'ParseTable' => [
						# Field				Parser			Default			Key			Req
						['NAME',			\&Parse_ABNF_qdescrs,	[],			'NAME',			0,],
						['DESC',			\&Parse_ABNF_qdstring,	undef,			'DESC',			0,],
						['OBSOLETE',			\&Return_1,		0,			'OBSOLETE',		0,],
						['SUP',				\&Parse_ABNF_oid,	[],			'SUP',			0,],
						['EQUALITY',			\&Parse_ABNF_oid,	[],			'EQALITY',		0,],
						['ORDERING',			\&Parse_ABNF_oid,	[],			'ORDERING',		0,],
						['SUBSTR',			\&Parse_ABNF_oid,	[],			'SUBSTR',		0,],
						['SYNTAX',			\&Parse_ABNF_noidlen,	[],			'-SYNTAXLEN',		0,],
						['SINGLE-VALUE',		\&Return_1,		0,			'SINGLE-VALUE',		0,],
						['COLLECTIVE',			\&Return_1,		0,			'COLLECTIVE',		0,],
						['NO-USER-MODIFICATION',	\&Return_1,		0,			'NO-USER-MODIFICATION',	0,],
						['USAGE',			\&Parse_ABNF_usage,	'userApplications',	'USAGE',		0,],
						],
				'Check_Isolated' => \&Check_Isolated_AttributeTypes,
				'Check_ReferencedTypeTable' => [
						#Field				Lookup			Type
						['SUP',				\&Lookup_nameoid,	'attributeTypes',	],
						['EQUALITY',			\&Lookup_nameoid,	'matchingRules',	],
						['ORDERING',			\&Lookup_nameoid,	'matchingRules',	],
						['SUBSTR',			\&Lookup_nameoid,	'matchingRules',	],
						['-DSYNTAX',			\&Lookup_nameoid,	'ldapSyntaxes',		],
						],
				},
		lc('matchingRules') => {
				'ParseElementID' => [\&Parse_TypeOid, '-OID'],
				'ParseTable' => [
						#Field				Parser			Default			Key			Req
						['NAME',			\&Parse_ABNF_qdescrs,	[],			'NAME',			0,],
						['DESC',			\&Parse_ABNF_qdstring,	undef,			'DESC',			0,],
						['OBSOLETE',			\&Return_1,		0,			'OBSOLETE',		0,],
						['SYNTAX',			\&Parse_ABNF_numoid,	[],			'SYNTAX',		1,],
						],
				'Check_Isolated' => undef,
				'Check_ReferencedTypeTable' => [
						#Field				Lookup			Type
						['SYNTAX',			\&Lookup_nameoid,	'ldapSyntaxes',		],
						],
				},
		lc('matchingRuleUse') => {
				'ParseElementID' => [\&Parse_TypeOid, '-OID'],
				'ParseTable' => [
						#Field				Parser			Default			Key			Req
						['NAME',			\&Parse_ABNF_qdescrs,	[],			'NAME',			0,],
						['DESC',			\&Parse_ABNF_qdstring,	undef,			'DESC',			0,],
						['OBSOLETE',			\&Return_1,		0,			'OBSOLETE',		0,],
						['APPLIES',			\&Parse_ABNF_oids,	[],			'APPLIES',		1,],
						],
				'Check_Isolated' => undef,
				'Check_ReferencedTypeTable' => [
						#Field				Lookup			Type
						['APPLIES',			\&Lookup_nameoid,	'attributeTypes',	],
						],
				},
		lc('ldapSyntaxes') => {
				'ParseElementID' => [\&Parse_TypeOid, '-OID'],
				'ParseTable' => [
						#Field				Parser			Default			Key			Req
						['DESC',			\&Parse_ABNF_qdstring,	undef,			'DESC',			0,],
						],
				'Check_Isolated' => undef,
				'Check_ReferencedTypeTable' => [
						#Field				Lookup			Type
						],
				},
		lc('dITContentRules') => {
				'ParseElementID' => [\&Parse_TypeOid, '-OID'],
				'ParseTable' => [
						#Field				Parser			Default			Key			Req
						['NAME',			\&Parse_ABNF_qdescrs,	[],			'NAME',			0,],
						['DESC',			\&Parse_ABNF_qdstring,	undef,			'DESC',			0,],
						['OBSOLETE',			\&Return_1,		0,			'OBSOLETE',		0,],
						['AUX',				\&Parse_ABNF_oids,	[],			'AUX',			0,],
						['MUST',			\&Parse_ABNF_oids,	[],			'MUST',			0,],
						['MAY',				\&Parse_ABNF_oids,	[],			'MAY',			0,],
						['NOT',				\&Parse_ABNF_oids,	[],			'NOT',			0,],
						],
				'Check_Isolated' => undef,
				'Check_ReferencedTypeTable' => [
						#Field				Lookup			Type
						['AUX',				\&Lookup_nameoid,	'objectClasses',	],
						['MUST',			\&Lookup_nameoid,	'attributeTypes',	],
						['MAY',				\&Lookup_nameoid,	'attributeTypes',	],
						['NOT',				\&Lookup_nameoid,	'attributeTypes',	],
						],
				},
		lc('dITStructureRules') => {
				'ParseElementID' => [\&Parse_RuleID, '-RULEID'],
				'ParseTable' => [
						#Field				Parser			Default			Key			Req
						['NAME',			\&Parse_ABNF_qdescrs,	[],			'NAME',			0,],
						['DESC',			\&Parse_ABNF_qdstring,	undef,			'DESC',			0,],
						['OBSOLETE',			\&Return_1,		0,			'OBSOLETE',		0,],
						['FORM',			\&Parse_ABNF_oid,	[],			'FORM',			1,],
						['SUP',				\&Parse_ABNF_ruleids,	[],			'SUP',			0,],
						],
				'Check_Isolated' => undef,
				'Check_ReferencedTypeTable' => [
						#Field				Lookup			Type
						['FORM',			\&Lookup_nameoid,	'nameforms',		],
						['SUP',				\&Lookup_ruleid,	'ditstructurerules',	],
						],
				},
		lc('nameForms') => {
				'ParseElementID' => [\&Parse_TypeOid, '-OID'],
				'ParseTable' => [
						#Field				Parser			Default			Key			Req
						['NAME',			\&Parse_ABNF_qdescrs,	[],			'NAME',			0,],
						['DESC',			\&Parse_ABNF_qdstring,	undef,			'DESC',			0,],
						['OBSOLETE',			\&Return_1,		0,			'OBSOLETE',		0,],
						['OC',				\&Parse_ABNF_oid,	[],			'OC',			1,],
						['MUST',			\&Parse_ABNF_oids,	[],			'MUST',			1,],
						['MAY',				\&Parse_ABNF_oids,	[],			'MAY',			0,],
						],
				'Check_Isolated' => undef,
				'Check_ReferencedTypeTable' => [
						#Field				Lookup			Type
						['OC',				\&Lookup_nameoid,	'objectClasses',	],
						['MUST',			\&Lookup_nameoid,	'attributeTypes',	],
						['MAY',				\&Lookup_nameoid,	'attributeTypes',	],
						],
				},
		);


sub Parse_LDAP_RFC4512_Schema_Type
	{
	my ($key, $value, $parsetableref) = @_;

	my $obj = {
		'-Type' => $key,
		};

	if ($value !~ /^\((.*)\)\s*$/)
		{
		return undef;
		}

	$value = $1;

	if (!defined($value = &{$parsetableref->{'ParseElementID'}->[0]}($obj, $parsetableref->{'ParseElementID'}->[1], $value)))
		{
		return undef;
		}

	if (!defined($value = TableParse($parsetableref->{'ParseTable'}, $obj, $value)))
		{
		return undef;
		}

	if (!defined($value = Parse_ABNF_extensions($obj, $value)))
		{
		return undef;
		}

	if ($value !~ /^\s*$/)
		{
		return undef;
		}

	if (defined $parsetableref->{'Check_Isolated'})
		{
		$obj = $parsetableref->{'Check_Isolated'}($obj);
		}

	return $obj;
	}


#######################################


foreach my $key (keys %Table_LDAP_RFC4512_Schema_Type_Parse)
	{
	$SchemaElements{$key} = {};
	$SchemaElements{$key}->{'Descriptions'} = [];
	}


while (@ARGV)
	{
	my $schemafile = shift @ARGV;
	my ($item, $line);

	open(my $fh, '<', $schemafile) || next;
	while ((($item, $line) = unwrap($fh)) && $line)
		{
		if ($item !~ /^($RE_keystring)\s*:\s*(\S.*)$/)
			{
			next;
			}

		my ($attribute, $value) = ($1, $2);

		if (exists($Table_LDAP_RFC4512_Schema_Type_Parse{lc($attribute)}))
			{
			my $obj;
			if (!defined($obj = Parse_LDAP_RFC4512_Schema_Type(
					lc($attribute),
					$value,
					$Table_LDAP_RFC4512_Schema_Type_Parse{lc($attribute)},
					)))
				{
				say "ERROR: '$attribute' declaration ignored due to parse error";
				say "\tLine $line of '$schemafile'";
				next;
				}

			$obj->{'-Defined'} = [$schemafile, $line];
			push @{$SchemaElements{lc($attribute)}->{'Descriptions'}}, $obj;
			}
		else
			{
#			say $item;
			}
		}

	close($fh);
	}


# Basic schema element checks.

foreach my $key (sort keys %SchemaElements)
	{
	say scalar(@{$SchemaElements{$key}->{'Descriptions'}}), "\t'$key' elements declared";

	$SchemaElements{$key}->{'Names'} = {};
	$SchemaElements{$key}->{'RuleIds'} = {};

	foreach my $element (@{$SchemaElements{$key}->{'Descriptions'}})
		{
		if (exists $element->{'-OID'})
			{
			my $oid = lc($element->{'-OID'});
			$Oids{$oid} = [] if !exists $Oids{$oid};
			push @{$Oids{$oid}}, $element;
			}

		if (exists $element->{'NAME'})
			{
			foreach my $name (@{$element->{'NAME'}})
				{
				$name = lc($name);
				$SchemaElements{$key}->{'Names'}->{$name} = [] if !exists $SchemaElements{$key}->{'Names'}->{$name};
				push @{$SchemaElements{$key}->{'Names'}->{$name}}, $element;

				$Names{$name} = {} if !exists $Names{$name};
				$Names{$name}->{$key} = undef;
				}
			}

		if (exists $element->{'-RULEID'})
			{
			$SchemaElements{$key}->{'RuleIds'}->{$element->{'-RULEID'}} = [] if !exists $SchemaElements{$key}->{'RuleIds'}->{$element->{'-RULEID'}};
			push @{$SchemaElements{$key}->{'RuleIds'}->{$element->{'-RULEID'}}}, $element;
			}
		}
	}


foreach my $oid (sort {CmpOids($a, $b)} keys %Oids)
	{
	next if scalar(@{$Oids{$oid}}) == 1;

	say "ERROR: OID '$oid' declared multiple times:";
	foreach my $elem (@{$Oids{$oid}})
		{
		say "\t'", $elem->{'-Type'},"'";
		say "\t\tLine: ", $elem->{'-Defined'}->[1], " in file: '", $elem->{'-Defined'}->[0], "'";
		}
	}


foreach my $key (sort keys %SchemaElements)
	{
	foreach my $name (sort keys %{$SchemaElements{$key}->{'Names'}})
		{
		next if scalar(@{$SchemaElements{$key}->{'Names'}->{$name}}) == 1;

		say "ERROR: Name '$name' declared multiple times:";
		foreach my $elem (@{$SchemaElements{$key}->{'Names'}->{$name}})
			{
			say "\t'", $elem->{'-Type'},"'";
			say "\t\tLine: ", $elem->{'-Defined'}->[1], " in file: '", $elem->{'-Defined'}->[0], "'";
			}
		}
	}


foreach my $key (sort keys %SchemaElements)
	{
	foreach my $ruleid (sort keys %{$SchemaElements{$key}->{'RuleIds'}})
		{
		next if scalar(@{$SchemaElements{$key}->{'RuleIds'}->{$ruleid}}) == 1;

		say "ERROR: RuleID '$ruleid' declared multiple times:";
		foreach my $elem (@{$SchemaElements{$key}->{'RuleIds'}->{$ruleid}})
			{
			say "\t'", $elem->{'-Type'},"'";
			say "\t\tLine: ", $elem->{'-Defined'}->[1], " in file: '", $elem->{'-Defined'}->[0], "'";
			}
		}
	}


foreach my $name (sort keys %Names)
	{
	next if scalar(keys %{$Names{$name}}) == 1;

	say "WARNING: Name '$name' declared as multiple schema element types:";
	foreach my $key (sort keys %{$Names{$name}})
		{
		foreach my $elem (@{$SchemaElements{$key}->{'Names'}->{$name}})
			{
			say "\t'", $elem->{'-Type'}, "'";
			say "\t\tLine: ", $elem->{'-Defined'}->[1], " in file: '", $elem->{'-Defined'}->[0], "'";
			}
		}
	}


# Basic referenced schema element type checks


foreach my $key (sort keys %Table_LDAP_RFC4512_Schema_Type_Parse)
	{
	$key = lc($key);
	my $refdtypetable = $Table_LDAP_RFC4512_Schema_Type_Parse{$key}->{'Check_ReferencedTypeTable'};

	foreach my $element (@{$SchemaElements{$key}->{'Descriptions'}})
		{
		foreach my $fieldrefchecktable (@{$refdtypetable})
			{
			my ($field, $lookup, $type) = @{$fieldrefchecktable};
			$type = lc($type);

			next if !exists $element->{$field};

			foreach my $ref (@{$element->{$field}})
				{
				$ref = lc($ref);

				my $targets = &{$lookup}($type, $ref);

				if (!scalar(@{$targets}))
					{
					say "ERROR: Schema element of type '$type' not found referenced as '$ref':";
					say "\t'", $element->{'-Type'}, "'";
					say "\t\tLine: ", $element->{'-Defined'}->[1], " in file: '", $element->{'-Defined'}->[0], "'";
					next;
					}

				foreach my $target (@{&{$lookup}($type, $ref)})
					{
					if ($target->{'-Type'} ne $type)
						{
						say "ERROR: Found schema element type of '$target->{'-Type'}' instead of expected type of '$type' when referenced as '$ref':";
						say "\t'", $element->{'-Type'}, "'";
						say "\t\tLine: ", $element->{'-Defined'}->[1], " in file: '", $element->{'-Defined'}->[0], "'";
						}
					}
				}
			}
		}
	}


__END__


use Data::Dumper;
$Data::Dumper::Sortkeys = 1;
say Dumper($var1, ...);
say '';


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

attributetypes = (
	-OID		=>	$,	# required:		# oid
	NAME		=>	[],	# optional: []		# strings
	DESC		=>	$,	# optional: undef	# string
	OBSOLETE	=>	bool,	# optional: false
	SUP		=>	[],	# optional: undef	# oid
	EQUALITY	=>	[],	# optional: undef	# oid
	ORDERING	=>	[],	# optional: undef	# oid
	SUBSTR		=>	[],	# optional: undef	# oid
	-SYNTAXLEN	=>	[[]],	# optional: undef	# oid
	SINGLE-VALUE	=>	bool,	# optional: false
	COLLECTIVE	=>	bool,	# optional: false
	RO		=>	bool,	# optional: false
	USAGE		=>	$,	# optional: 'userApplications'
	-DSYNTAX	=>	[],	# optional: []		# oid
	-DLENMINMAX	=>	$,	# optional: undef	# number
	-X		=>	{[]},	# optional: []		# hashrefs
	-Defined	=>	[],	# schema file & line declared
	-Type		=>	'attributetypes',

	-EQUALITY	=>	$,	# declared or inherited value
	-ORDERING	=>	$,	# declared or inherited value
	-SUBSTR		=>	$,	# declared or inherited value
	-SYNTAX		=>	$,	# declared or inherited value

	-TC_supers	=>	[],	# oids from SUP chain
	-TC_schemas	=>	[],	# schema files transitive closure
	);


objectclasses = (
	-OID		=>	$,	# required:		# oid
	NAME		=>	[],	# optional: []		# strings
	DESC		=>	$,	# optional: undef
	OBSOLETE	=>	bool,	# optional: false
	SUP		=>	[],	# optional: []		# oids
	ABSTRACT	=>	bool,	# optional: false
	STRUCTURAL	=>	bool,	# optional: false
	AUXILIARY	=>	bool,	# optional: false
	MUST		=>	[],	# optional: []		# oids
	MAY		=>	[],	# optional: []		# oids
	-X		=>	{[]},	# optional: []		# hashrefs
	-Defined	=>	[],	# schema file & line declared
	-Type		=>	'objectclasses',

	-TC_supers	=>	[],	# oids from SUP chains
	-TC_schemas	=>	[],	# schema files transitive closure
	-TC_musts	=>	[],	# oids, transitive closure
	-TC_mays	=>	[],	# oids, transitive closure
	);


matchingrules = (
	-OID		=>	$,	# required:		# oid
	NAME		=>	[],	# optional: []		# strings
	DESC		=>	$,	# optional: undef	# string
	OBSOLETE	=>	bool,	# optional: false
	SYNTAX		=>	[],	# required: []		# oid
	-X		=>	{[]},	# optional: []		# hashrefs
	-Defined	=>	[],	# schema file & line declared
	-Type		=>	'matchingrules',
	);


matchingruleuse = (
	-OID		=>	$,	# required:		# oid
	NAME		=>	[],	# optional: []		# strings
	DESC		=>	$,	# optional: undef	# string
	OBSOLETE	=>	bool,	# optional: false
	APPLIES		=>	[],	# required: []		# oids
	-X		=>	{[]},	# optional: []		# hashrefs
	-Defined	=>	[],	# schema file & line declared
	-Type		=>	'matchingruleuse',
	);


ldapsyntaxes = (
	-OID		=>	$,	# required:		# oid
	DESC		=>	$,	# optional: undef	# string
	-X		=>	{[]},	# optional: []		# hashrefs
	-Defined	=>	[],	# schema file & line declared
	-Type		=>	'ldapsyntaxes',
	);


ditcontentrules = (
	-OID		=>	$,	# required:		# oid
	NAME		=>	[],	# optional: []		# strings
	DESC		=>	$,	# optional: undef	# string
	OBSOLETE	=>	bool,	# optional: false
	AUX		=>	[],	# optional: []		# oids
	MUST		=>	[],	# optional: []		# oids
	MAY		=>	[],	# optional: []		# oids
	NOT		=>	[],	# optional: []		# oids
	-X		=>	{[]},	# optional: []		# hashrefs
	-Defined	=>	[],	# schema file & line declared
	-Type		=>	'ditcontentrules',
	);


ditstructurerules = (
	-RULEID		=>	[],	# required:		# numbers
	NAME		=>	[],	# optional: []		# strings
	DESC		=>	$,	# optional: undef	# string
	OBSOLETE	=>	bool,	# optional: false
	FORM		=>	[],	# required:		# oid
	SUP		=>	[],	# optional: []		# ruleids
	-X		=>	{[]},	# optional: {[]}	# hashrefs
	-Defined	=>	[],	# schema file & line declared
	-Type		=>	'ditstructurerules',
	);


nameforms = (
	-OID		=>	$,	# required:		# oid
	NAME		=>	[],	# optional: []		# strings
	DESC		=>	$,	# optional: undef	# string
	OBSOLETE	=>	bool,	# optional: false
	OC		=>	[],	# required: []		# oid
	MUST		=>	[],	# required: []		# oids
	MAY		=>	[],	# optional: []		# oids
	-X		=>	{[]},	# optional: {[]}	# hashrefs
	-Defined	=>	[],	# schema file & line declared
	-Type		=>	'nameforms',
	);

