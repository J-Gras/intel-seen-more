@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event new_connection(c: connection)
	{
	if ( get_conn_transport_proto(c$id) == udp )
		{
		Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
		Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
		}
	}
