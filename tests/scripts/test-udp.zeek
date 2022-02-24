#
# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace ../../../scripts/seen/udp %INPUT
# @TEST-EXEC: btest-diff intel.log

# Load default seen scripts
@load frameworks/intel/seen

event zeek_init()
	{
	Intel::insert([$indicator="224.0.0.252", $indicator_type=Intel::ADDR,
		$meta=[$source="source1"]]);
	}
