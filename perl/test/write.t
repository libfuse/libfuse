#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
plan tests => 15;
my ($data);
chdir($_point);
undef $/; # slurp it all
# create file
system("echo frogbing >writefile");

# fetch contents of file
ok(open(FILE,"writefile"),"open");
$data = <FILE>;
close(FILE);
is(length($data),9,"right amount read");
is($data,"frogbing\n","right data read");

# overwrite part
ok(open(FILE,'+<',"writefile"),"open");
ok(seek(FILE,2,0),"seek");
ok(print(FILE "ib"),"print");
close(FILE);

# fetch contents of file
ok(open(FILE,"writefile"),"open");
$data = <FILE>;
close(FILE);
is(length($data),9,"right amount read");
is($data,"fribbing\n","right data read");

# overwrite part, append some
ok(open(FILE,'+<',"writefile"),"open");
ok(seek(FILE,7,0),"seek");
ok(print(FILE "gle"),"print");
close(FILE);

# fetch contents of file
ok(open(FILE,"writefile"),"open");
$data = <FILE>;
close(FILE);
is(length($data),10,"right amount read");
is($data,"fribbingle","right data read");

# kill file
unlink("writefile");
