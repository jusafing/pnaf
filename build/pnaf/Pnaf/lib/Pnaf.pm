package Pnaf;

use 5.000;
use strict;

require Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
@ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Pnaf ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
%EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

@EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

@EXPORT = qw(
	
);

$VERSION = '0.01';


# Preloaded methods go here.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Pnaf - Passive Network Audit Framework

=head1 SYNOPSIS

  use Pnaf;

=head1 DESCRIPTION
    B<PNAF> is a framework intended to provide the capability of getting
    a security assessment of network plattforms (small, medium and large)
    by analysing in-depth the network traffic (in a passive way) and by
    providing a high-level interpretation in an automated way. It combines
    differet analysis techniques, algorithms and technologies. To this
    extent, the framework is intended to achieve the following goals:
    Architecture:
	a. To be a flexible, scalable and modular framework
        b. To provide accurate analysis of network plattforms
	c. To provide a useful API in order to develop further features
           and improvements
    Functional:
        a. Summary of the Security Level of the network
	b. Findings of anomalous activities
        c. Findings of security audit policy
	d. Findings of impact analysis
        e. Summary of security recommendations
	f. Reference of evidence



=head2 EXPORT

None by default.



=head1 SEE ALSO

See README file on main PNAF directory release

=head1 AUTHOR

Javier Santillan, E<lt>jusafing@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by antimorris



=cut
