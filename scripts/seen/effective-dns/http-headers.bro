@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations
@load base/utils/addrs

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( is_orig )
		{
		switch ( name )
			{
			case "HOST":
			# The split is done to remove the occasional port value that shows up here (see also base script)
			local host = split_string1(value, /:/)[0];
			if ( !is_valid_ip(host) )
				Intel::seen([$indicator=DomainTLD::effective_domain(host),
					     $indicator_type=Intel::EFFECTIVE_DOMAIN,
					     $conn=c,
					     $where=HTTP::IN_HOST_HEADER]);
			break;
			}
		}
	}
