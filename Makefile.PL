use ExtUtils::MakeMaker;


# The following code to check the module and version number was borrowed
# from Graham Barr's perl-ldap module set.

my $missing = 0;
$| = 1;

sub check_module {
    my($module,$version) = @_;
    print substr("$module ............................",0,30);
    my $ok = eval {
	my $file = $module;
    $file =~ s#::#/#g;
	require $file . ".pm";
	$module->VERSION($version) if defined $version;
	1;
    };
    $missing++ unless $ok;
    print $ok ? "ok\n" : "** FAILED **\n$@\n";
    $ok;
}


print "Checking for installed modules\n\n";

check_module('Authen::Smb',0.9) or print <<"EOF","\n";
Authen::Smb version 0.9 or greater required.  All versions of Authen::Smb below 0.9
have possible buffer overflows in the underlying smbval library.
EOF

if ($missing) {
    print "\n",<<"EOF", "\n";
Please visit CPAN to obtain up to date version of the missing modules.
EOF
exit;
}



WriteMakefile(
    'NAME'	=> 'Apache::AuthenSmb',
    'VERSION_FROM' => 'AuthenSmb.pm', # finds $VERSION
    'dist' => {COMPRESS => 'gzip', SUFFIX => 'gz'}
);
