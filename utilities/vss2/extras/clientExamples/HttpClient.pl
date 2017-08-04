#!/usr/local/bin/perl

# Required perl modules:
#	lib-www
#	LWP::Protocol::https
#	IO::Socket::SSL

#
# The restful service endpoint
#
my $rsUrl = 'https://vssapi.treasury.gov/vss/rest/';
#
# For JSON attribute: validationPolicy
#
# This JSON attribute value MUST NOT be null
#
my $loa1Oid = '2.16.840.1.101.10.2.18.2.1.1';
my $loa2Oid = '2.16.840.1.101.10.2.18.2.1.2';
my $loa3Oid = '2.16.840.1.101.10.2.18.2.1.3';
my $loa4Oid = '2.16.840.1.101.10.2.18.2.1.4';

#
# For JSON attribute: clientPort
#
# This JSON attribute value MUST NOT be null
#
my $clientPort = "443";

my $clientCert  = "-----BEGIN CERTIFICATE-----
MIIHhzCCBm+gAwIBAgIEVFek1zANBgkqhkiG9w0BAQsFADCBgjELMAkGA1UEBhMC
VVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVu
dCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9y
aXRpZXMxEDAOBgNVBAsTB09DSU8gQ0EwHhcNMTUwODI3MTkzMDQyWhcNMTgwMzI2
MTk1NzU5WjCBrTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVu
dDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1cnkxJTAjBgNVBAsT
HEJ1cmVhdSBvZiB0aGUgRmlzY2FsIFNlcnZpY2UxDzANBgNVBAsTBlBlb3BsZTEn
MA0GA1UEBRMGNDAzNjExMBYGA1UEAxMPVG9kZCBFLiBKb2huc29uMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz5wocTnElfxUCjYZsYu/e6cYKSEz4/+s
Vci385ykoq9Dw378qjOfcraXSVqczP9Pyr0G9sYehlULNCm6iZKq+oE3RuF3jWjP
m5h8RIXCDKjfZ83Zt5pCpWhPPsaxjfLpi/FXJdoJIr1eDMAF4SL/6IY8UUgYQrbi
go9jtEseWFo7tKbAYPXf9INr73OMSlSMjTD4A8Ja8f9bA7kB+CQojQ28pFpCCzns
+wxZuxBcZ64GD8O4EgLQN5fpfImvNkl77moy6q83XfFh0cW448Ez2esRV/x7rZxe
4kXW1cXyi5AJ/sJfxpbOq+fWnpDtQMhQaF2U8B3BanwDYRcB0ip6EQIDAQABo4ID
1jCCA9IwDgYDVR0PAQH/BAQDAgeAMCUGA1UdIAQeMBwwDAYKYIZIAWUDAgEDDTAM
BgpghkgBZQMCAQUEMCUGA1UdJQQeMBwGCisGAQQBgjcUAgIGCCsGAQUFBwMCBgRV
HSUAMBAGCWCGSAFlAwYJAQQDAQEAMIIBCAYIKwYBBQUHAQEEgfswgfgwMAYIKwYB
BQUHMAKGJGh0dHA6Ly9wa2kudHJlYXMuZ292L3RvY2FfZWVfYWlhLnA3YzCBoAYI
KwYBBQUHMAKGgZNsZGFwOi8vbGRhcC50cmVhcy5nb3Yvb3U9T0NJTyUyMENBLG91
PUNlcnRpZmljYXRpb24lMjBBdXRob3JpdGllcyxvdT1EZXBhcnRtZW50JTIwb2Yl
MjB0aGUlMjBUcmVhc3VyeSxvPVUuUy4lMjBHb3Zlcm5tZW50LGM9VVM/Y0FDZXJ0
aWZpY2F0ZTtiaW5hcnkwIQYIKwYBBQUHMAGGFWh0dHA6Ly9vY3NwLnRyZWFzLmdv
djCBhgYDVR0RBH8wfaAwBgorBgEEAYI3FAIDoCIMIFRPREQuSk9ITlNPTkBGSVND
QUwuVFJFQVNVUlkuR09WgSBUb2RkLkpvaG5zb25AZmlzY2FsLnRyZWFzdXJ5Lmdv
dqAnBghghkgBZQMGBqAbBBnSAkRYIQ5tXmYQRaFoWgEIQ5IRpIICEMP/MIIBiQYD
VR0fBIIBgDCCAXwwJ6AloCOGIWh0dHA6Ly9wa2kudHJlYXMuZ292L09DSU9fQ0E0
LmNybDCCAU+gggFLoIIBR6SBlzCBlDELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu
Uy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1
cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxEDAOBgNVBAsT
B09DSU8gQ0ExEDAOBgNVBAMTB0NSTDE0NzKGgapsZGFwOi8vbGRhcC50cmVhcy5n
b3YvY249Q1JMMTQ3MixvdT1PQ0lPJTIwQ0Esb3U9Q2VydGlmaWNhdGlvbiUyMEF1
dGhvcml0aWVzLG91PURlcGFydG1lbnQlMjBvZiUyMHRoZSUyMFRyZWFzdXJ5LG89
VS5TLiUyMEdvdmVybm1lbnQsYz1VUz9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0
O2JpbmFyeTAfBgNVHSMEGDAWgBTXzihMyCRqVkZbdWWLZ8T6yOCIpTAdBgNVHQ4E
FgQUpd8+Pas9Z6VJx8B26F/7GeAeeREwDQYJKoZIhvcNAQELBQADggEBAJLTp2KB
Rl+oCnB77VGXLtEZxG+KqtYB61uTZ6RjQvbeZxE82B2FHXv6w6S6EiUOPyaFA9ZA
GKiR4RG1KTJpwcv2WyVdJ26aAhBoEPoR7iEMeAYKLPcERrq4nP22CrEICEwPS5vV
ulS6Kd1caDbHXDizZvXxGH2B5un9+N497A0C0IR29Rn73sEz5kQGwzLaXEEqeUBy
ilnG+59Iv0Ayk+QmAm5iXeRMPfrAl42vko/0q5y23oN9qmA9rv5MsThw0Jh25u31
en8bcrtuJqyjnWNaUFvuwaX2GmNdh+UeUvRGZolHq82ZAQC6uzDI1eJoZtZ0L+jy
qtQyHrT9LPkqvao=
-----END CERTIFICATE-----
";

# Remove new-lines and BEGIN/End tags
$clientCert =~ s/-----.+?-----|\n//g;

my $x509CertificateList = "{\"x509Certificate\":\"${clientCert}\"}";

my $json = "{\"validationPolicy\":\"${loa1Oid}\",\"wantBackList\":\[\],\"x509CertificateList\":\[${x509CertificateList}\]}";
print "LOA1 Request:\n";
print "$json\n\n";
print "LOA1 Response:\n";
print geturl($rsUrl,$json) . "\n\n";

my $json = "{\"validationPolicy\":\"${loa2Oid}\",\"wantBackList\":\[\],\"x509CertificateList\":\[${x509CertificateList}\]}";
print "LOA2 Request:\n";
print "$json\n\n";
print "LOA2 Response:\n";
print geturl($rsUrl,$json) . "\n\n";

my $json = "{\"validationPolicy\":\"${loa3Oid}\",\"wantBackList\":\[\],\"x509CertificateList\":\[${x509CertificateList}\]}";
print "LOA3 Request:\n";
print "$json\n\n";
print "LOA3 Response:\n";
print geturl($rsUrl,$json) . "\n\n";

my $json = "{\"validationPolicy\":\"${loa4Oid}\",\"wantBackList\":\[\],\"x509CertificateList\":\[${x509CertificateList}\]}";
print "LOA4 Request:\n";
print "$json\n\n";
print "LOA4 Response:\n";
print geturl($rsUrl,$json) . "\n\n";

sub geturl{
	my $URL = shift;
	my $JSON = shift;
	use LWP;
	## Uncomment the following line to display SSL/TLS debugging information to STDOUT
	#use IO::Socket::SSL 'debug30';
	my $userAgent = LWP::UserAgent->new(
			ssl_opts => {
				verify_hostname => 0,
			}
		);
	$userAgent->agent("Custom Perl Testing Script - bcarroll");
	$userAgent->env_proxy; # Use HTTP Proxy Environment settings (http_proxy, http_proxy_user, http_proxy_pass)
	my $request = HTTP::Request->new(POST => $URL);
	$request->content_type('application/json');
	$request->content($JSON);
	my $response = $userAgent->request($request);
	if ($response->is_success) {
		return($response->content);
	} else {
		return($response->status_line);
	}
}
