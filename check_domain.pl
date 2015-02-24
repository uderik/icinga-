#!/usr/bin/env perl

use Net::DNS;
use Net::Domain::ExpireDate;
use Time::Seconds;
use Time::Piece;

use strict;
use warnings;

my $domain               = $ARGV[0];    # domain name from command line
my $check_expire         = 1;           # allow to check domain days expire
my $expire_warn_days     = 30;          # days to expire when warn
my $expire_critical_days = 7;           # days to expire when crit
my $check_serials   = 1;   # allow to check domain dns serials compare
my $check_zone_axfr = 1;   # allow to check domain dns zone transfer available


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

if ( !$domain ) {
    print <<EOF;
usage: $0 domain name
sample: $0 yandex.ru
EOF
    exit;
}

if ($check_expire) {

    ( $message, $status ) = &domain_expiration();
    if ( $ERRORS{$exit_status} < $ERRORS{$status} ) {
        $exit_status = $status;
    }
    $exit_message = $exit_message . "[ $message $status ]"

}

my $res = Net::DNS::Resolver->new( tcp_timeout => 10, udp_timeout => 10 );
my $rr;
my @ns_list;
my $reply;
@ns_list = &get_ns_list();

if ($check_serials) {
    ( $message, $status ) = &check_ns_serials();
    if ( $ERRORS{$exit_status} < $ERRORS{$status} ) {
        $exit_status = $status;
    }
    $exit_message = $exit_message . "[ $message $status ]";
}
if ($check_zone_axfr) {
    ( $message, $status ) = &check_zone_axfr();
    if ( $ERRORS{$exit_status} < $ERRORS{$status} ) {
        $exit_status = $status;
    }
    $exit_message = $exit_message . "[ $message $status ]";
}

print "$exit_status ", $exit_message, "[ ns list: @ns_list ]\n";
exit $ERRORS{$exit_status};

###############

sub domain_expiration() {
    my $dom_exp_date      = expire_date($domain);
    my $cur_date          = localtime;
    my $dom_exp_sec_left  = $dom_exp_date - $cur_date;
    my $dom_exp_days_left = $dom_exp_sec_left->days;
    $dom_exp_days_left = sprintf( "%.0f", $dom_exp_days_left );
    if ( $expire_critical_days >= $dom_exp_days_left ) {
        return ( "domain expires via $dom_exp_days_left days", "CRITICAL" );
    }
    if ( $expire_warn_days >= $dom_exp_days_left ) {
        return ( "domain expires via $dom_exp_days_left days", "WARNING" );
    }
    return ( "domain expires via $dom_exp_days_left days", "OK" );
}

sub get_ns_list {
### get ns list
    $reply = $res->query( "$domain", "NS" );
    if ($reply) {

        foreach $rr ( grep { $_->type eq 'NS' } $reply->answer ) {
            @ns_list = ( @ns_list, $rr->nsdname );
        }
    }
    else {
        print "query failed: ", $res->errorstring;
        exit $ERRORS{'CRITICAL'};
    }
    return @ns_list;
}

sub check_ns_serials {
    my $rr;
    my $ns;
    my @ns_serials;

### get and check ns serial

    foreach $ns (@ns_list) {

        $res->nameservers($ns);

        $reply = $res->query( "$domain", "SOA" );
        if ($reply) {
            foreach $rr ( $reply->answer ) {
                my $serial = $rr->serial;
                @ns_serials = ( @ns_serials, $rr->serial );
                if ( $ns_serials[0] != $serial ) {
                    return (
                        "server: $ns_list[0] serial: $ns_serials[0] != server $ns: 
                        . $rr->serial", "CRITICAL"
                    );
                }
            }
        }
        else {
            return ( "ns serial query error: $res->errorstring", "OK" );
        }
    }
    return ( "ns serial: $ns_serials[0]", "OK" );
}

sub check_zone_axfr {
    my $ns;
### check axfr
    foreach $ns (@ns_list) {
        $res->nameservers($ns);
        my @zone = $res->axfr("$domain");
        if (@zone) {
            return ( "zone tranfer allowed from: $ns", "WARNING" );
        }
    }
    return ( "no zone transfers", "OK" );
}
