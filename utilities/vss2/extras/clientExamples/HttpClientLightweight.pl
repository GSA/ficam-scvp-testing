#!/usr/local/bin/perl

# Required perl modules:
#	lib-www
#	LWP::Protocol::https
#	IO::Socket::SSL

#
# The restful service endpoint
#
my $rsUrl = 'https://accpiv.treasury.gov/vss/rest/validate/lightweight';
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
# For JSON attribute: clientAddress
#
# This JSON attribute value MAY be null
#
my $clientAddress = "172.30.30.1";
#
# For JSON attribute: clientPort
#
# This JSON attribute value MAY be null
#
my $clientPort = "443";
#
# For JSON attribute: clientPort
#
# This JSON attribute value MUST NOT be null
#
my $clientCert  = "-----BEGIN CERTIFICATE-----
MIIHlDCCBnygAwIBAgIEVFZlczANBgkqhkiG9w0BAQsFADCBgjELMAkGA1UEBhMC
VVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVu
dCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9y
aXRpZXMxEDAOBgNVBAsTB09DSU8gQ0EwHhcNMTUwNDEwMTU1NzM4WhcNMTgwNDEw
MTYyNzM4WjCBnTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVu
dDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1cnkxJTAjBgNVBAsT
HEJ1cmVhdSBvZiB0aGUgRmlzY2FsIFNlcnZpY2UxEDAOBgNVBAsTB0RldmljZXMx
FjAUBgNVBAMTDXBraS50cmVhcy5nb3YwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDHJzYjjEnEi/UBUVokkO9uWuDAbgrSqpprt389A3DYRrJXFYHr84/T
GUjarT3sek2glfHcvpZU5lvPes39TugCQh2tm5BTbHIdK8pYhBPmv9c5pyRwVgu3
1k+aCShPkP+K8dWjxchND5WgD5xtmI3Q2H8dDTNEWAkByVUTn1TQneCs29MyK3WM
sMWIgb8EkTJDQB9EAT/Z9tg0gETMi7CnGXitkzZrKkaHpSdLLuB9D7QCJUU+skTt
sgFSJRrHfFlFUmD/B+7Os8s8YPuBIc+Sr9PaoqRlDhlCzLVV3hCz1IH+spmDjvBd
D9GBCxRnU0cq6A2mXdNNolyh+Jlx8QA5AgMBAAGjggPzMIID7zAOBgNVHQ8BAf8E
BAMCBaAwFwYDVR0gBBAwDjAMBgpghkgBZQMCAQUDMBEGCWCGSAGG+EIBAQQEAwIG
QDATBgNVHSUEDDAKBggrBgEFBQcDATCCAQgGCCsGAQUFBwEBBIH7MIH4MDAGCCsG
AQUFBzAChiRodHRwOi8vcGtpLnRyZWFzLmdvdi90b2NhX2VlX2FpYS5wN2MwgaAG
CCsGAQUFBzAChoGTbGRhcDovL2xkYXAudHJlYXMuZ292L291PU9DSU8lMjBDQSxv
dT1DZXJ0aWZpY2F0aW9uJTIwQXV0aG9yaXRpZXMsb3U9RGVwYXJ0bWVudCUyMG9m
JTIwdGhlJTIwVHJlYXN1cnksbz1VLlMuJTIwR292ZXJubWVudCxjPVVTP2NBQ2Vy
dGlmaWNhdGU7YmluYXJ5MCEGCCsGAQUFBzABhhVodHRwOi8vb2NzcC50cmVhcy5n
b3YwewYDVR0RBHQwcoEcY3NhLXRlYW1AZmlzY2FsLnRyZWFzdXJ5LmdvdoIQcGtp
LnRyZWFzdXJ5LmdvdoIQcGtpLmRpbWMuZGhzLmdvdoINcGtpLnRyZWFzLmdvdoEf
ZWNiLWhvc3RpbmdAZmlzY2FsLnRyZWFzdXJ5LmdvdjCCAYkGA1UdHwSCAYAwggF8
MCegJaAjhiFodHRwOi8vcGtpLnRyZWFzLmdvdi9PQ0lPX0NBMy5jcmwwggFPoIIB
S6CCAUekgZcwgZQxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1l
bnQxIzAhBgNVBAsTGkRlcGFydG1lbnQgb2YgdGhlIFRyZWFzdXJ5MSIwIAYDVQQL
ExlDZXJ0aWZpY2F0aW9uIEF1dGhvcml0aWVzMRAwDgYDVQQLEwdPQ0lPIENBMRAw
DgYDVQQDEwdDUkwxNDA5hoGqbGRhcDovL2xkYXAudHJlYXMuZ292L2NuPUNSTDE0
MDksb3U9T0NJTyUyMENBLG91PUNlcnRpZmljYXRpb24lMjBBdXRob3JpdGllcyxv
dT1EZXBhcnRtZW50JTIwb2YlMjB0aGUlMjBUcmVhc3VyeSxvPVUuUy4lMjBHb3Zl
cm5tZW50LGM9VVM/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdDtiaW5hcnkwKwYD
VR0QBCQwIoAPMjAxNTA0MTAxNTU3MzhagQ8yMDE4MDQxMDE2MjczOFowHwYDVR0j
BBgwFoAUohOo5cYHVGwkPU63Kyeip3Eata8wHQYDVR0OBBYEFLCGnBLCk5FM1GDj
PtQ+bFom4NaPMBkGCSqGSIb2fQdBAAQMMAobBFY4LjEDAgOoMA0GCSqGSIb3DQEB
CwUAA4IBAQBJaNGCj579wUfnR7td2hVTakKgebMtPX+H5hm0g67ucLfia9o5PGAo
fHM+y0aP6LixG/gJ/3at1rkOslrY06EFLkPuKB5Io6Hr5++1nixKSHZd7esj9TRi
QhRXhsyYjHYtIw0o3TO/TCQF2Ay7LLHWTI8QuhMNUMsXT2/7nPwSgIKXos77o4X0
+tFw85tR69h8Eqv5PFH8AAr5DYqrp49IkjkIgEpes19hfM9x0gHjcIpVnm0W+fE+
B0Nh65AH4o2Gu04L+hOq0Ond2RJOhFGd5g4vxgQLGNn9YCsCaEtMBxwwGfyEIZfQ
DBIMQWVLy/vEoJahxje3kRK4HOH6OJn5
-----END CERTIFICATE-----";
# Remove new-lines and BEGIN/End tags
$clientCert =~ s/-----.+?-----|\n//g;
#
# For JSON attribute: clientMetadata
#
# This JSON attribute value MAY be null
#
my $clientMetadata = "{\"User-Agent\":\"Mozilla/5.0\",\"Accept-Language\":\"en-US,en\",\"clientAddress\":\"${clientAddress}\",\"clientPort\":\"${clientPort}\"}";
#
my $json  = "{\"validationPolicy\":\"${loa1Oid}\",\"clientCertificate\":\"${clientCert}\",\"clientMetadata\":${clientMetadata}}";
print "LOA1 Request:\n";
print "$json\n\n";
print "LOA1 Response:\n";
my $loa1Token = geturl($rsUrl,$json);
print "$loa1Token\n\n";
my $json  = "{\"validationPolicy\":\"${loa2Oid}\",\"clientCertificate\":\"${clientCert}\",\"clientMetadata\":${clientMetadata}}";
print "LOA2 Request:\n";
print "$json\n\n";
print "LOA2 Response:\n";
my $loa2Token = geturl($rsUrl,$json);
print "$loa2Token\n\n";
my $json  = "{\"validationPolicy\":\"${loa3Oid}\",\"clientCertificate\":\"${clientCert}\",\"clientMetadata\":${clientMetadata}}";
print "LOA3 Request:\n";
print "$json\n\n";
print "LOA3 Response:\n";
my $loa3Token = geturl($rsUrl,$json);
print "$loa3Token\n\n"; 
my $json  = "{\"validationPolicy\":\"${loa4Oid}\",\"clientCertificate\":\"${clientCert}\",\"clientMetadata\":${clientMetadata}}";
print "LOA4 Request:\n";
print "$json\n\n";
print "LOA4 Response:\n";
my $loa4Token = geturl($rsUrl,$json);
print "$loa4Token\n\n"; 

sub geturl{
	my $URL = shift;
	my $JSON = shift;
	use LWP;
	my $userAgent = LWP::UserAgent->new();
	$userAgent->agent("Custom Perl Testing Script - BWC");
	$userAgent->env_proxy; # Use HTTP Proxy Environment settings (http_proxy, http_proxy_user, http_proxy_pass)
	my $request = HTTP::Request->new(POST => $URL);
	$request->content_type('application/json');
	$request->content($JSON);
	my $response = $userAgent->request($request);
	if ($response->is_success) {
		return($response->content);
	} else {
		return($response->status_line, "\n");
	}
}
