use ExtUtils::MakeMaker;


print "Checking for Smb ........ ";
eval {
    require Smb;
};
if ($@) {
    print "failed\n";
    print <<EOT;
$@
The SMB module is required for this module to work properly.
You can obtain this module from Patrick Michael Kane which
last time I looked (4/17/98) was located at
http://www.fatal.org/~modus/
EOT
    exit;
} else {
    print " ok\n";
}



WriteMakefile(
    'NAME'	=> 'Apache::AuthenSmb',
    'VERSION_FROM' => 'AuthenSmb.pm', # finds $VERSION
    'dist' => {COMPRESS => 'gzip', SUFFIX => 'gz'}
);
