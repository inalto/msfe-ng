#!/usr/bin/perl
# The DSN the logging plugin builds: `localhost` is the Unix socket for both
# drivers and DBD::MariaDB refuses a port with it ("port cannot be specified
# when host is localhost or embedded") — so the port is only added for a real
# host. Found on a cPanel host with DBD::MariaDB: every connect failed.
use strict;
use warnings;
use Test::More;
use FindBin;

require "$FindBin::Bin/../MSFENG.pm";

my %local = (db_name => 'msfe_ng', db_host => 'localhost', db_port => 3306);
is(MailScanner::CustomConfig::dsn_for('MariaDB', \%local),
    'DBI:MariaDB:database=msfe_ng;host=localhost', 'MariaDB + localhost: no port');
is(MailScanner::CustomConfig::dsn_for('mysql', \%local),
    'DBI:mysql:database=msfe_ng;host=localhost', 'mysql + localhost: no port either');

my %remote = (db_name => 'msfe_ng', db_host => '10.0.0.5', db_port => 3307);
is(MailScanner::CustomConfig::dsn_for('MariaDB', \%remote),
    'DBI:MariaDB:database=msfe_ng;host=10.0.0.5;port=3307', 'real host keeps the port');
is(MailScanner::CustomConfig::dsn_for('mysql', {%remote, db_port => 0}),
    'DBI:mysql:database=msfe_ng;host=10.0.0.5', 'port 0/unset is left out');

done_testing;
