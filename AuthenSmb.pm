package Apache::AuthenSmb;

use strict;
#use Apache::Constants ':common';
use Authen::Smb;

$Apache::AuthenSmb::VERSION = '0.70';

############################################
# here is where we start the new code....
############################################
use mod_perl ;

# use Apache::Constants qw(:common);
# setting the constants to help identify which version of mod_perl
# is installed
use constant MP2 => ($mod_perl::VERSION >= 1.99);

# test for the version of mod_perl, and use the appropriate libraries
BEGIN {
        if (MP2) {
                require Apache::Const;
                require Apache::Access;
                require Apache::Connection;
                require Apache::Log;
                require Apache::RequestRec;
                require Apache::RequestUtil;
                Apache::Const->import(-compile => 'HTTP_UNAUTHORIZED','OK');
        } else {
                require Apache::Constants;
                Apache::Constants->import('HTTP_UNAUTHORIZED','OK');
        }
}
##################### end modperl code ######################

sub handler {
    my $r = shift;
    my($res, $sent_pwd) = $r->get_basic_auth_pw;
    return $res if $res; #decline if not Basic

    my $name = MP2 ? $r->user : $r->connection->user;

    my $pdc = $r->dir_config('myPDC');
    my $bdc = $r->dir_config('myBDC') || $pdc;
    my $domain = $r->dir_config('myDOMAIN') || "WORKGROUP";

    if ($name eq "") {
	$r->note_basic_auth_failure;
        MP2 ? $r->log_error("Apache::AuthenSmb - No Username Given", $r->uri) : $r->log_reason("Apache::AuthenSmb - No Username Given", $r->uri);
        return MP2 ? Apache::HTTP_UNAUTHORIZED : Apache::Constants::HTTP_UNAUTHORIZED;
    }

    if (!$pdc) {
	$r->note_basic_auth_failure;
        MP2 ? $r->log_error("Apache::AuthenSmb - Configuration error, no PDC", $r->uri) : $r->log_reason("Apache::AuthenSmb - Configuration error, no PDC", $r->uri);
         return MP2 ? Apache::HTTP_UNAUTHORIZED : Apache::Constants::HTTP_UNAUTHORIZED;
    }

    my $return = Authen::Smb::authen($name,
			     $sent_pwd,
			     $pdc,
			     $bdc,
			     $domain);

    unless($return == 0) {
	$r->note_basic_auth_failure;
	MP2 ? $r->log_error("user $name: password mismatch", $r->uri) : $r->log_reason("user $name: password mismatch", $r->uri);
	 return MP2 ? Apache::HTTP_UNAUTHORIZED : Apache::Constants::HTTP_UNAUTHORIZED;
    }

    unless (@{ $r->get_handlers("PerlAuthzHandler") || []}) {
	$r->push_handlers(PerlAuthzHandler => \&authz);
    }

    return MP2 ? Apache::OK : Apache::Constants::OK;
}

sub authz {
    my $r = shift;
    my $requires = $r->requires;
    return (MP2 ? Apache::OK : Apache::Constants::OK) unless $requires;

    my $name = MP2 ? $r->user : $r->connection->user;

    for my $req (@$requires) {
        my($require, @rest) = split /\s+/, $req->{requirement};

	#ok if user is one of these users
	if ($require eq "user") {
	    return (MP2 ? Apache::OK : Apache::Constants::OK) if grep $name eq $_, @rest;
	}
	#ok if user is simply authenticated
	elsif ($require eq "valid-user") {
	    return MP2 ? Apache::OK : Apache::Constants::OK;
	}
    }
    
    $r->note_basic_auth_failure;
    $r->log_reason("user $name: not authorized", $r->uri);
     return MP2 ? Apache::HTTP_UNAUTHORIZED : Apache::Constants::HTTP_UNAUTHORIZED;

}

1;

__END__

=head1 NAME

Apache::AuthenSMB - mod_perl NT Authentication module


=head1 SYNOPSIS

    <Directory /foo/bar>
    # This is the standard authentication stuff
    AuthName "Foo Bar Authentication"
    AuthType Basic

    # Variables you need to set, you must set at least
    # the myPDC variable, the DOMAIN defaults to WORKGROUP	
    PerlSetVar myPDC workgroup-pdc
    PerlSetVar myBDC workgroup-bdc
    PerlSetVar myDOMAIN WORKGROUP

    PerlAuthenHandler Apache::AuthenSmb

    # Standard require stuff, only user and 
    # valid-user work currently
    require valid-user
    </Directory>

    These directives can be used in a .htaccess file as well.

    If you wish to use your own PerlAuthzHandler then the require 
    directive should follow whatever handler you use.

= head1 DESCRIPTION

This perl module is designed to work with mod_perl and the Authen::Smb
module by Patrick Michael Kane (See CPAN).  You need to set your PDC,
BDC, and NT domain name for the script to function properly.  You MUST
set a PDC, if no BDC is set it defaults to the PDC, if no DOMAIN is
set it defaults to WORKGROUP.

If you are using this module please let me know, I'm curious how many
people there are that need this type of functionality.

=head1 AUTHOR

Michael Parker <parkerm@pobox.com>
Ported by Shannon Eric Peevey <speeves@unt.edu>

=head1 COPYRIGHT

Copyright (c) 1998 Michael Parker, Tandem Computers.

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
