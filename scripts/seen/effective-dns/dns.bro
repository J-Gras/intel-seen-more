@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	Intel::seen([$indicator=DomainTLD::effective_domain(query),
	             $indicator_type=Intel::EFFECTIVE_DOMAIN,
	             $conn=c,
	             $where=DNS::IN_REQUEST]);
}
