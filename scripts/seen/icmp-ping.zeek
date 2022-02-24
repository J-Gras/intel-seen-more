@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
	{
	Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
	Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
	print c$id;
	}

event icmp_echo_reply(c: connection, info: icmp_info, id: count, seq: count, payload: string)
	{
	Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
	Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
	}
