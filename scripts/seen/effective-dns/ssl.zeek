@load base/frameworks/intel
@load base/protocols/ssl
@load policy/frameworks/intel/seen/where-locations

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
	{
	if ( is_orig && c?$ssl && c$ssl?$server_name )
		Intel::seen([$indicator=DomainTLD::effective_domain(c$ssl$server_name),
		             $indicator_type=Intel::EFFECTIVE_DOMAIN,
		             $conn=c,
		             $where=SSL::IN_SERVER_NAME]);
	}

event ssl_established(c: connection)
	{
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	if ( c$ssl$cert_chain[0]$x509?$certificate && c$ssl$cert_chain[0]$x509$certificate?$cn )
	@if ( Version::at_least("4.1") )
		Intel::seen([
			$indicator=DomainTLD::effective_domain(c$ssl$cert_chain[0]$x509$certificate$cn),
			$indicator_type=Intel::EFFECTIVE_DOMAIN,
			$fuid=c$ssl$cert_chain[0]$fuid,
			$conn=c,
			$where=X509::IN_CERT]);
	@else
		Intel::seen([
			$indicator=DomainTLD::effective_domain(c$ssl$cert_chain[0]$x509$certificate$cn),
			$indicator_type=Intel::EFFECTIVE_DOMAIN,
			$fuid=c$ssl$cert_chain_fuids[0],
			$conn=c,
			$where=X509::IN_CERT]);
	@endif
	}
