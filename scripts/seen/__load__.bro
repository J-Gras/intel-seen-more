
##! Load all seen scripts if dependencies are available.

@ifdef ( DomainTLD::effective_domain )
@load ./effective-dns
@else
event bro_init()
	{
	Reporter::error("Effective DNS matching cannot be loaded: " +
		"Package Domain-TLD missing.");
	}
@endif

@load ./udp
@load ./conn-tcp
