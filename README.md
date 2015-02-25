# icinga-scripts
icinga/nagios monitoring scripts
--------------------------------

./check-domain.pl - check domain: expires, dns serials and zone transfer

perl modules:
* Net::DNS;
* Net::Domain::ExpireDate;
* Time::Seconds;
* Time::Piece;

./check_cert_expire.pl - check ssl certificate expiration date, no certificate validation

perl modules:
* Net::SSL::ExpireDate;
* Getopt::Long;
