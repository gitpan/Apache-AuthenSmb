package Apache::AuthenSmb;

use strict;
use Apache::Constants ':common';
use Authen::Smb;

$Apache::AuthenSmb::VERSION = '0.60';


sub handler {
    my $r = shift;
    my($res, $sent_pwd) = $r->get_basic_auth_pw;
    return $res if $res; #decline if not Basic

    my $name = $r->connection->user;

    my $pdc = $r->dir_config('myPDC');
    my $bdc = $r->dir_config('myBDC') || $pdc;
    my $domain = $r->dir_config('myDOMAIN') || "WORKGROUP";

    if ($name eq "") {
	$r->note_basic_auth_failure;
        $r->log_reason("Apache::AuthenSmb - No Username Given", $r->uri);
        return AUTH_REQUIRED;
    }

    if (!$pdc) {
	$r->note_basic_auth_failure;
        $r->log_reason("Apache::AuthenSmb - Configuration error, no PDC", $r->uri);
        return AUTH_REQUIRED;
    }

    my $return = Authen::Smb::authen($name,
			     $sent_pwd,
			     $pdc,
			     $bdc,
			     $domain);

    unless($return == 0) {
	$r->note_basic_auth_failure;
	$r->log_reason("user $name: password mismatch", $r->uri);
	return AUTH_REQUIRED;
    }

    unless (@{ $r->get_handlers("PerlAuthzHandler") || []}) {
	$r->push_handlers(PerlAuthzHandler => \&authz);
    }

    return OK;
}

sub authz {
    my $r = shift;
    my $requires = $r->requires;
    return OK unless $requires;

    my $name = $r->connection->user;

    for my $req (@$requires) {
        my($require, @rest) = split /\s+/, $req->{requirement};

	#ok if user is one of these users
	if ($require eq "user") {
	    return OK if grep $name eq $_, @rest;
	}
	#ok if user is simply authenticated
	elsif ($require eq "valid-user") {
	    return OK;
	}
    }
    
    $r->note_basic_auth_failure;
    $r->log_reason("user $name: not authorized", $r->uri);
    return AUTH_REQUIRED;

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

Michael Parker <parkerm@null.net>

=head1 COPYRIGHT

Copyright (c) 1998 Michael Parker, Tandem Computers.

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
