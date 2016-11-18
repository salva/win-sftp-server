#!/usr/bin/perl

use strict;
use warnings;
use File::Spec;
use Getopt::Long;
use Test::More;
use Net::SFTP::Foreign;
use Net::SFTP::Foreign::Constants qw(:flags);

my $save_err;
my $temp = "c:/temp";
my $wine;
my $delay = 0;

GetOptions("save-err|s" => \$save_err,
           "working-dir|w=s" => \$temp,
           "wine|i" => \$wine,
           "delay|d=i" => \$delay);

sub path_to_wine {
    my ($path) = @_;
    if ($wine) {
        $path =~ s{^([a-z]):}{"$ENV{HOME}/.wine/drive_" . lc $1}ei;
        diag "path $_[0] converted to $path";
    }
    return $path;
}

my $local_temp = path_to_wine $temp;
my $remote_dir = "w";
my $local_dir = "$local_temp/$remote_dir";

my $exe = File::Spec->rel2abs("sftp-server.exe");
my @cmd = $exe;
unshift @cmd, 'wine' if $wine;

my $errfh;
if ($save_err) {
    open $errfh, ">sftp-server-stderr.txt";
}
else {
    $save_err = \*STDERR;
}

mkdir $local_temp;
ok -d $local_temp;
ok(chdir $local_temp);


my $s = Net::SFTP::Foreign->new(open2_cmd => \@cmd, stderr_fh => $errfh);
diag "child pid: $s->{pid}";
sleep $delay;

ok($s->test_d("c:/temp"), "temp directory exists");
ok($s->test_d("c:\\temp"), "forward and back slashes are equivalent");
ok($s->test_d("C:\\tEmP"), "case does not matter either");

$s->mkdir($remote_dir);
ok -d $local_dir, "local dir is $local_dir";
is (path_to_wine($s->realpath($remote_dir)), $local_dir, "realpath");

ok $s->test_d($remote_dir), "remote working dir exists";
ok $s->setcwd($remote_dir), "setcwd";
is (path_to_wine($s->realpath(".")), $local_dir, "realpath");

my $rfn = "data.txt";
my $rfh = $s->open($rfn, SSH2_FXF_WRITE | SSH2_FXF_CREAT | SSH2_FXF_TRUNC);
ok $rfh, "open for writting";

my $rfh1 = $s->open($rfn, SSH2_FXF_WRITE|SSH2_FXF_APPEND);
ok $rfh1, "open for appending with FILE_SHARE_WRITE";

my $rfh2 = $s->open($rfn, SSH2_FXF_READ);
ok $rfh2, "open for reading with FILE_SHARE_WRITE";

my $data = <<EOD;
  La primavera ha venido,
  nadie sabe cómo ha sido
EOD

is((print {$rfh} $data), length $data, "print");
ok $s->fsync($rfh), "fsync";

ok(opendir my $ldh, $local_dir);
my @le = sort readdir $ldh;
close $ldh;

my $rdh = $s->opendir('.');
ok defined $rdh;
my @re = sort map { $_->{filename} } $s->readdir($rdh);

is "@re", "@le";

ok ($s->test_e($rfh));
ok (!$s->test_d($rfh));
my $a = $s->stat($rfn);
is $a->perm & 0777, 0600, sprintf("permissions 0%o", $a->perm);

$s->remove("r-$rfn");
ok (!$s->test_e("r-$rfn"), "new file is not there yet");
ok($s->rename($rfn, "r-$rfn"), "rename");
ok (!$s->test_e($rfn), "old file is gone");
ok ($s->test_e("r-$rfn"), "new file is there");
ok ($s->hardlink($rfn, "r-$rfn"), "hardlink");
ok ($s->test_e($rfn), "old file is there again");
ok ($s->remove("r-$rfn"), "unlink");
SKIP: {
    skip "DeleteFileW is lazy in Wine", 1 if $wine;
    ok (!$s->test_e("r-$rfn"), "new file is finally gone");
};

my $data1 = do { undef $/; <$rfh2> };
is ($data1, $data, "read");

is (tell $rfh2, length $data, "tell");
ok seek($rfh2, 0, 0), "seek";
is((print {$rfh1} $data), length $data, "append");
ok ($s->flush($rfh1), "fsync append");

my $data2 = do { undef $/; <$rfh2> };
is ($data2, "$data$data", "read appended");

my $a1 = $s->stat($rfh2);
ok($a1, "fstat");
is ($a1->size, 2 * length $data);
ok($s->truncate($rfn, length $data), "truncate");
my $a2 = $s->stat($rfn);
is ($a2->size, length $data, "stat");
ok($s->truncate($rfh, 0), "ftruncate");
my $a3 = $s->stat($rfh1);
is ($a3->size, 0, "fstat again");
is ((print {$rfh1} $data), length $data, "append after truncate");
ok ($s->fsync($rfh1), "fsync again");
my $a4 = $s->stat($rfn);
is ($a4->size, length $data);
ok (!defined <$rfh2>, "reading at EOF");
ok $s->seek($rfh2, 0, 0), "seek to beginning";
my $data3 = do { undef $/; <$rfh2> };
is ($data3, $data, "reread from the beginning");

$s->remove("sl1-$rfn");
ok(!$s->test_e("sl1-$rfn"), "symbolic link does not exist");
ok($s->symlink("sl1-$rfn", $s->realpath($rfn)), "abs symlink");
#ok($s->symlink("sl1-$rfn", $rfn));
is($s->readlink("sl1-$rfn"), $s->realpath($rfn));

$s->remove("sl2-$rfn");
ok(!$s->test_e("sl2-$rfn"), "symbolic link does not exist");
ok($s->symlink("sl2-$rfn", $rfn), "relative symlink");
is($s->readlink("sl2-$rfn"), $rfn, "read relative symlink");

my $a5 = $s->lstat("sl2-$rfn");
ok($a5, "lstat");
is($a5 && $a5->perm, 0120777, "symlink perms");
is($a5 && $a5->size, 0, "symlink size");

my $a6 = $s->stat("sl2-$rfn");
ok($a6, "stat");
my $perm6 = ($a6 && $a6->perm) // 0;
isnt($perm6, 0120777, "resolved symlink perms");
is($perm6 & 0170000, 0100000, "resolved symlink is a regular file");
is($perm6 & 0700, 0600, "resolved symlink has read and write permissions");
is($a6 && $a6->size, length($data), "resolved symlink size");

my $fh7 = $s->open("sl2-$rfn", SSH2_FXF_READ);
ok($fh7, "open following link");

my $a7 = $s->stat($fh7); # this is a fstat under the hood
ok($a7);
my $perm7 = ($a7 && $a7->perm) // 0;
is ($perm7 & 0170000, 0100000, "fstat regular file");
is ($perm7 & 0700, 0600, "fstat retursn read and write permissions");

my $old_time = time() - 100;

ok($s->utime($fh7, $old_time, $old_time), "utime with fsetstat");
$a7 = $s->stat($fh7);
ok($a7, "fstat again");
my $mtime7 = ($a7 && $a7->mtime) // 0;
is($mtime7, $old_time, "fstat mtime");

$old_time += 10;
ok($s->utime($rfh, $old_time, $old_time), "utime with setstat");
my $a8 = $s->stat($rfh);
ok($a8, "stat 8");
my $mtime8 = ($a8 && $a8->mtime) // 0;
is ($mtime8, $old_time);

my $a9 = $s->stat("sl1-$rfn");
ok($a9, "stat 9");
my $mtime9 = ($a9 && $a9->mtime) // 0;
is($mtime9, $old_time, "mtime following symlink");

done_testing();
