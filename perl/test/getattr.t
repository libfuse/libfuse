#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
use Data::Dumper;
plan tests => 28;
my ($a, $b) = ("$_real/wibble","$_point/wibble");
`touch $b`;
is(-A "$a", -A "$b", '-A'); # 1
is(-B "$a", -B "$b", '-B'); # 2
is(-C "$a", -C "$b", '-C'); # 3
is(-M "$a", -M "$b", '-M'); # 4
is(-O "$a", -O "$b", '-O'); # 5
is(-R "$a", -R "$b", '-R'); # 6
is(-S "$a", -S "$b", '-S'); # 7
is(-T "$a", -T "$b", '-T'); # 8
is(-W "$a", -W "$b", '-W'); # 9
is(-X "$a", -X "$b", '-X'); # 10
is(-b "$a", -b "$b", '-b'); # 11
is(-c "$a", -c "$b", '-c'); # 12
is(-d "$a", -d "$b", '-d'); # 13
is(-e "$a", -e "$b", '-e'); # 14
is(-f "$a", -f "$b", '-f'); # 15
is(-g "$a", -g "$b", '-g'); # 16
is(-k "$a", -k "$b", '-k'); # 17
is(-l "$a", -l "$b", '-l'); # 18
is(-o "$a", -o "$b", '-o'); # 19
is(-p "$a", -p "$b", '-p'); # 20
is(-r "$a", -r "$b", '-r'); # 21
is(-s "$a", -s "$b", '-s'); # 22
is(-t "$a", -t "$b", '-t'); # 23
is(-u "$a", -u "$b", '-u'); # 24
is(-w "$a", -w "$b", '-w'); # 25
is(-x "$a", -x "$b", '-x'); # 26
is(-z "$a", -z "$b", '-z'); # 27
my (@astat, @bstat);
@astat = stat("$a");
@bstat = stat("$b");
# dev and inode can legally change
shift(@astat); shift(@astat);
shift(@bstat); shift(@bstat);
is(join(" ",@astat),join(" ",@bstat),"stat()");
`rm -f $a`;
