#
# @TEST-EXEC: zeek -C -r $TRACES/icmp-ping.pcap ../../../scripts/seen/icmp-ping %INPUT
# @TEST-EXEC: btest-diff intel.log

# Load default seen scripts
@load frameworks/intel/seen

event zeek_init()
	{
	Intel::insert([$indicator="10.0.0.1", $indicator_type=Intel::ADDR,
		$meta=[$source="source1"]]);
	}


