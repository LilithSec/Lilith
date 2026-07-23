package Lilith::AutoEscalate;

use 5.006;
use strict;
use warnings;
use JSON qw( decode_json );

=head1 NAME

Lilith::AutoEscalate - Compile auto escalation rules and evaluate them with Rule::Engine.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Lilith::AutoEscalate;

    # dies with a message if the rule is not usable
    Lilith::AutoEscalate->check_rule( $rule );

    # arrayref of { rule => $rule_row, event => $alert_row } for every match
    my $matches = Lilith::AutoEscalate->evaluate(
        rules  => $rule_rows,      # rows from the auto_escalations table
        events => $alert_rows,     # alert row hash refs (as returned by search)
    );

=head1 DESCRIPTION

A auto escalation rule is stored in the C<rule> column of a
C<auto_escalations> row as a JSON object of the form

    {
        "match": { ...condition node... },
        "actions": [ { "escalate_to": [ "soc-hook", 3 ], "note": "..." } ]
    }

The B<match> is a tree of condition nodes. A node is one of

    { "all":  [ node, ... ] }    # every child must match
    { "any":  [ node, ... ] }    # at least one child must match
    { "not":  node }             # the child must not match
    { "field": <name>, "op": <op>, "value": <value> }   # a leaf test

A leaf B<field> names an alert column (C<malscore>, C<signature>,
C<src_ip>, ...) or a dotted path into the decoded C<raw> payload
(C<raw.alert.severity>). The supported B<op>s are

    ==  !=            string equality, numeric when both sides are numeric
    >  >=  <  <=      numeric comparison
    regex            the field value matches the value as a regular expression
    in               the field value equals one of the value list
    contains         the field (string) contains the value as a substring, or
                     the field (array) contains the value as an element
    exists           the field is (value true) or is not (value false) defined

Rules are never evaluated as Perl; a leaf only ever does hash lookups
and the fixed comparisons above, so a rule is safe to accept from the
web UI. C<evaluate> compiles each rule's match into a coderef and runs
them as a L<Rule::Engine> ruleset, ordered by C<priority> (lower
first); when a matching rule has C<stop_on_match> set, later rules are
not evaluated for that alert.

=head1 METHODS

=cut

# the comparison operators a leaf may use
my %OPS = map { $_ => 1 } ( '==', '!=', '>', '>=', '<', '<=', 'regex', 'in', 'contains', 'exists' );

=head2 check_rule

Validates a rule hash ref, dieing with a message describing the first
problem found. Returns 1 when the rule is usable. Called on the create
and update paths before a rule is stored.

    Lilith::AutoEscalate->check_rule( $rule );

=cut

sub check_rule {
	my ( $class, $rule ) = @_;

	if ( ref($rule) ne 'HASH' ) {
		die("rule must be a object\n");
	}

	if ( ref( $rule->{match} ) ne 'HASH' ) {
		die("rule is missing a 'match' object\n");
	}
	$class->_check_node( $rule->{match}, 'match' );

	if ( ref( $rule->{actions} ) ne 'ARRAY' || !@{ $rule->{actions} } ) {
		die("rule is missing a non-empty 'actions' array\n");
	}
	my $i = 0;
	foreach my $action ( @{ $rule->{actions} } ) {
		my $where = 'actions[' . $i . ']';
		if ( ref($action) ne 'HASH' ) {
			die( $where . " must be a object\n" );
		}
		if ( ref( $action->{escalate_to} ) ne 'ARRAY' || !@{ $action->{escalate_to} } ) {
			die( $where . " is missing a non-empty 'escalate_to' array\n" );
		}
		foreach my $target ( @{ $action->{escalate_to} } ) {
			if ( !defined($target) || ref($target) || $target eq '' ) {
				die( $where . " 'escalate_to' items must be target names or ids\n" );
			}
		}
		if ( exists( $action->{note} ) && ref( $action->{note} ) ) {
			die( $where . " 'note' must be a string\n" );
		}
		$i++;
	} ## end foreach my $action ( @{ $rule->{actions} } )

	return 1;
} ## end sub check_rule

# validates a condition node, dieing with the path to the first problem
sub _check_node {
	my ( $class, $node, $where ) = @_;

	if ( ref($node) ne 'HASH' ) {
		die( $where . " must be a object\n" );
	}

	my @combinators = grep { exists $node->{$_} } ( 'all', 'any', 'not' );
	if ( @combinators > 1 ) {
		die( $where . " may only have one of 'all', 'any', or 'not'\n" );
	}

	# a node mixing a combinator with leaf keys would have the leaf part
	# silently ignored by compile, so it does not do what was written
	if (@combinators) {
		my @leaf_keys = grep { exists $node->{$_} } ( 'field', 'op', 'value' );
		if (@leaf_keys) {
			die(      $where
					. " may not mix '"
					. $combinators[0]
					. "' with the leaf keys "
					. join( ', ', map { "'" . $_ . "'" } @leaf_keys )
					. "\n" );
		}
	} ## end if (@combinators)

	if ( exists( $node->{all} ) || exists( $node->{any} ) ) {
		my $key = exists( $node->{all} ) ? 'all' : 'any';
		if ( ref( $node->{$key} ) ne 'ARRAY' || !@{ $node->{$key} } ) {
			die( $where . " '" . $key . "' must be a non-empty array\n" );
		}
		my $i = 0;
		foreach my $child ( @{ $node->{$key} } ) {
			$class->_check_node( $child, $where . '.' . $key . '[' . $i . ']' );
			$i++;
		}
		return 1;
	} ## end if ( exists( $node->{all} ) || exists( $node...))

	if ( exists( $node->{not} ) ) {
		$class->_check_node( $node->{not}, $where . '.not' );
		return 1;
	}

	# a leaf
	if ( !defined( $node->{field} ) || ref( $node->{field} ) || $node->{field} eq '' ) {
		die( $where . " leaf is missing a 'field' name\n" );
	}
	if ( !defined( $node->{op} ) || !$OPS{ $node->{op} } ) {
		die( $where . " leaf has a missing or unknown 'op' (allowed: " . join( ', ', sort keys %OPS ) . ")\n" );
	}
	if ( $node->{op} eq 'in' ) {
		if ( ref( $node->{value} ) ne 'ARRAY' ) {
			die( $where . " leaf with op 'in' needs a 'value' array\n" );
		}
		foreach my $item ( @{ $node->{value} } ) {
			if ( !defined($item) || ref($item) ) {
				die( $where . " leaf with op 'in' must have only defined scalar 'value' items\n" );
			}
		}
	} ## end if ( $node->{op} eq 'in' )

	# the comparison ops numify the value at compile time, so a non-numeric
	# value would validate cleanly but silently compare against 0
	if ( $node->{op} eq '>' || $node->{op} eq '>=' || $node->{op} eq '<' || $node->{op} eq '<=' ) {
		if (  !defined( $node->{value} )
			|| ref( $node->{value} )
			|| $node->{value} !~ /^-?[0-9]+(?:\.[0-9]+)?$/ )
		{
			die( $where . " leaf with op '" . $node->{op} . "' needs a numeric 'value'\n" );
		}
	}

	# ==, != and contains compare against a single scalar
	if ( ( $node->{op} eq '==' || $node->{op} eq '!=' || $node->{op} eq 'contains' )
		&& ref( $node->{value} ) )
	{
		die( $where . " leaf with op '" . $node->{op} . "' needs a scalar 'value'\n" );
	}
	if ( $node->{op} eq 'regex' ) {
		if ( !defined( $node->{value} ) || ref( $node->{value} ) ) {
			die( $where . " leaf with op 'regex' needs a string 'value'\n" );
		}
		my $pattern = $node->{value};
		eval { qr/$pattern/; 1 } or die( $where . " leaf 'value' is not a valid regex: " . $@ );
	}
	if ( $node->{op} ne 'exists' && $node->{op} ne 'in' && !exists( $node->{value} ) ) {
		die( $where . " leaf with op '" . $node->{op} . "' needs a 'value'\n" );
	}

	return 1;
} ## end sub _check_node

=head2 compile

Compiles a rule's match into a coderef that takes a alert row hash ref
and returns true when it matches. Used by evaluate; exposed so the
match can be tested against a single event without Rule::Engine.

    my $matches = Lilith::AutoEscalate->compile( $rule );
    if ( $matches->( $alert_row ) ) { ... }

=cut

sub compile {
	my ( $class, $rule ) = @_;

	my $match = ref($rule) eq 'HASH' ? $rule->{match} : undef;
	if ( ref($match) ne 'HASH' ) {
		return sub { 0 };
	}

	return $class->_compile_node($match);
} ## end sub compile

# turns a validated condition node into a coderef of sub ($obj) -> bool
sub _compile_node {
	my ( $class, $node ) = @_;

	if ( ref($node) ne 'HASH' ) {
		return sub { 0 };
	}

	if ( exists( $node->{all} ) ) {
		my @subs = map { $class->_compile_node($_) } @{ $node->{all} };
		return sub {
			my $obj = $_[0];
			foreach my $sub (@subs) {
				return 0 unless $sub->($obj);
			}
			return 1;
		};
	} ## end if ( exists( $node->{all} ) )

	if ( exists( $node->{any} ) ) {
		my @subs = map { $class->_compile_node($_) } @{ $node->{any} };
		return sub {
			my $obj = $_[0];
			foreach my $sub (@subs) {
				return 1 if $sub->($obj);
			}
			return 0;
		};
	} ## end if ( exists( $node->{any} ) )

	if ( exists( $node->{not} ) ) {
		my $sub = $class->_compile_node( $node->{not} );
		return sub { $sub->( $_[0] ) ? 0 : 1 };
	}

	return $class->_compile_leaf($node);
} ## end sub _compile_node

# turns a validated leaf node into a coderef of sub ($obj) -> bool
sub _compile_leaf {
	my ( $class, $node ) = @_;

	my $field = $node->{field};
	my $op    = $node->{op};
	my $value = $node->{value};

	if ( $op eq 'exists' ) {
		my $want = ( !exists( $node->{value} ) || $value ) ? 1 : 0;
		return sub {
			my $v = $class->_field_value( $_[0], $field );
			return ( ( defined($v) ? 1 : 0 ) == $want ) ? 1 : 0;
		};
	}

	if ( $op eq '>' || $op eq '>=' || $op eq '<' || $op eq '<=' ) {
		my $target = $value + 0;
		return sub {
			my $v = $class->_field_value( $_[0], $field );
			return 0 if !defined($v) || ref($v) || $v !~ /^-?\d+(?:\.\d+)?$/;
			my $n = $v + 0;
			return ( $op eq '>' ? $n > $target
				: $op eq '>=' ? $n >= $target
				: $op eq '<'  ? $n < $target
				: $n <= $target ) ? 1
				: 0;
		}; ## end sub
	} ## end if ( $op eq '>' || $op eq '>=' || $op eq '<'...)

	if ( $op eq '==' || $op eq '!=' ) {
		my $eq = ( $op eq '==' );
		return sub {
			my $v     = $class->_field_value( $_[0], $field );
			my $match = ( defined($v) && !ref($v) && _eq( $v, $value ) ) ? 1 : 0;
			return ( $eq ? $match : !$match ) ? 1 : 0;
		};
	}

	if ( $op eq 'regex' ) {
		my $re = qr/$value/;
		return sub {
			my $v = $class->_field_value( $_[0], $field );
			return ( defined($v) && !ref($v) && $v =~ $re ) ? 1 : 0;
		};
	}

	if ( $op eq 'in' ) {
		my @list = @{$value};
		return sub {
			my $v = $class->_field_value( $_[0], $field );
			return 0 if !defined($v) || ref($v);
			foreach my $item (@list) {
				return 1 if _eq( $v, $item );
			}
			return 0;
		};
	} ## end if ( $op eq 'in' )

	# contains
	return sub {
		my $v = $class->_field_value( $_[0], $field );
		return 0 if !defined($v);
		if ( ref($v) eq 'ARRAY' ) {
			foreach my $item ( @{$v} ) {
				return 1 if !ref($item) && _eq( $item, $value );
			}
			return 0;
		}
		return 0 if ref($v);
		return ( index( $v, $value ) >= 0 ) ? 1 : 0;
	}; ## end sub
} ## end sub _compile_leaf

# equality that is numeric when both sides look numeric, else string eq
sub _eq {
	my ( $a, $b ) = @_;

	return 0 if !defined($a) || !defined($b);

	if (   $a =~ /^-?\d+(?:\.\d+)?$/
		&& $b =~ /^-?\d+(?:\.\d+)?$/ )
	{
		return ( $a + 0 == $b + 0 ) ? 1 : 0;
	}

	return ( $a eq $b ) ? 1 : 0;
} ## end sub _eq

# resolves a dotted field path against a alert row, decoding the raw JSON
# column when a path descends into it
sub _field_value {
	my ( $class, $obj, $field ) = @_;

	return undef if !defined($field);

	my $cur = $obj;
	foreach my $part ( split( /\./, $field ) ) {
		if ( ref($cur) eq 'HASH' ) {
			$cur = $cur->{$part};
		} elsif ( ref($cur) eq 'ARRAY' && $part =~ /^\d+$/ ) {
			$cur = $cur->[$part];
		} else {
			return undef;
		}

		# the raw column arrives as a JSON string; decode it when a path
		# steps into it so raw.* leaves can see the decoded structure
		if ( defined($cur) && !ref($cur) && $part eq 'raw' ) {
			my $decoded;
			eval { $decoded = decode_json($cur); };
			$cur = $decoded if defined($decoded);
		}
	} ## end foreach my $part ( split( /\./, $field ) )

	return $cur;
} ## end sub _field_value

=head2 evaluate

Compiles the given rules and runs them against the given events as a
L<Rule::Engine> ruleset. Returns a array ref with one hash ref per
match, each having the keys C<rule> (the rule row that matched) and
C<event> (the alert row it matched). Rules are evaluated in C<priority>
order (lower first, ties broken by id); a match on a rule with
C<stop_on_match> stops later rules from being evaluated for that alert.

    my $matches = Lilith::AutoEscalate->evaluate(
        rules  => $rule_rows,
        events => $alert_rows,
    );

=cut

sub evaluate {
	my ( $class, %opts ) = @_;

	my $rules  = ref( $opts{rules} ) eq 'ARRAY'  ? $opts{rules}  : [];
	my $events = ref( $opts{events} ) eq 'ARRAY' ? $opts{events} : [];

	require Rule::Engine::Session;
	require Rule::Engine::RuleSet;
	require Rule::Engine::Rule;

	my @ordered = sort {
		( defined( $a->{priority} ) ? $a->{priority} : 100 )
			<=> ( defined( $b->{priority} ) ? $b->{priority} : 100 )
			|| ( defined( $a->{id} ) ? $a->{id} : 0 ) <=> ( defined( $b->{id} ) ? $b->{id} : 0 )
	} @{$rules};

	my $session = Rule::Engine::Session->new;
	my @matches;
	$session->set_environment( 'matches', \@matches );
	$session->set_environment( 'stopped', {} );

	my $ruleset = Rule::Engine::RuleSet->new( name => 'auto' );

	foreach my $rule (@ordered) {
		my $condition = $class->compile( $rule->{rule} );
		my $stop      = $rule->{stop_on_match} ? 1 : 0;
		my $meta      = $rule;

		$ruleset->add_rule(
			Rule::Engine::Rule->new(
				name      => 'auto_' . ( defined( $rule->{id} ) ? $rule->{id} : ( $rule->{name} || 'rule' ) ),
				condition => sub {
					my ( $self, $sess, $obj ) = @_;
					my $key = defined( $obj->{id} ) ? $obj->{id} : "$obj";
					return 0 if $sess->get_environment('stopped')->{$key};
					return $condition->($obj) ? 1 : 0;
				},
				action => sub {
					my ( $self, $sess, $obj ) = @_;
					push( @{ $sess->get_environment('matches') }, { rule => $meta, event => $obj } );
					my $key = defined( $obj->{id} ) ? $obj->{id} : "$obj";
					$sess->get_environment('stopped')->{$key} = 1 if $stop;
				},
			)
		);
	} ## end foreach my $rule (@ordered)

	$session->add_ruleset( 'auto', $ruleset );
	$session->execute( 'auto', $events );

	return \@matches;
} ## end sub evaluate

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
