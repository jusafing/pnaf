#!/usr/bin/perl

use Crypt::RSA;

$rsa = new Crypt::RSA;

$id = shift || die("Usage: $0 <identity> <filename> [password]\n");
$outfile = shift || die("Usage: $0 <identity> <filename> [password]\n");
$passwd = shift || print("Enter password: "); <STDIN>; 

chomp $passwd;

if ( -f $outfile.public || -f $outfile.private ) { die("$outfile.[public|private] already exists\n"); }

print("Generating keypair for $id\n");
print("Storing in $outfile.public and $outfile.private\n\n");

my ($pubkey, $privkey) = $rsa->keygen (
        Identity  => $id,
        Size      => 1024,
        Password  => $passwd,
        Verbosity => 1,
	Filename  => $outfile,
    ) or die $rsa->errstr();

print("\n\nDone!\n");
