#!/usr/bin/env perl
#
#
use Net::SSL::ExpireDate;
use Getopt::Long;

use strict;
use warnings;

my $host                 = "";    # domain name from command line
my $port                 = "";    # tcp port
my $expire_warn_days     = 30;    # days to expire when warn
my $expire_critical_days = 7;     # days to expire when crit

GetOptions( 'host=s' => \$host, 'port=s' => \$port );

my %ERRORS = (
    'OK'        => 0,
    'WARNING'   => 1,
    'CRITICAL'  => 2,
    'UNKNOWN'   => 3,
    'DEPENDENT' => 4
);

my $exit_status  = 'OK';
my $exit_message = "";
my $status       = 0;
my $message      = "";

if ( !$host || !$port ) {
    print <<EOF;
Script to check ssl certificate expiration only, no validation tests

Usage: $0 --host ip --port ssl_port
Sample: $0 --host www.google.com --port 443 # check google cert
Sample: $0 --host smtp.gmail.com --port 465 # check google smtps cert
EOF
    exit;
}

( $message, $status ) = &check_cert_exp();

$exit_message = $exit_message . "[ $message $status ]";
$exit_status  = $status;

print "$exit_status ", $exit_message, "\n";
exit $ERRORS{$exit_status};

sub check_cert_exp() {

    my $cur_date = DateTime->now->epoch;
    my $ed = Net::SSL::ExpireDate->new( ssl => "$host:$port" );    # ssl
    my $cert_date_exp     = $ed->expire_date->epoch;
    my $cert_sec_exp_left = $cert_date_exp - $cur_date;

    my $cert_days_exp_left = int( $cert_sec_exp_left / ( 24 * 60 * 60 ) );

    if ( $expire_critical_days >= $cert_days_exp_left ) {
        return (
            "certificate for $host:$port expires via $cert_days_exp_left days",
            "CRITICAL"
        );
    }
    if ( $expire_warn_days >= $cert_days_exp_left ) {
        return (
            "certificate for $host:$port expires via $cert_days_exp_left days",
            "WARNING"
        );
    }
    return (
        "certificate for $host:$port expires via $cert_days_exp_left days",
        "OK" );
}
