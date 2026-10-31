redef enum Notice::Type += { UDP_Scan };

global udp_count: table[addr] of count &default=0;
global udp_notices: table[addr] of count &default=0;

event icmp_unreachable(c: connection, info: icmp_info, code: count, context: icmp_context)
	{
	if ( code == 3 && get_port_transport_proto(context$id$resp_p) == udp )
		{
		local src = context$id$orig_h;
		udp_count[src] += 1;

		if ( udp_count[src] == 20 )
			{
			NOTICE([$note=UDP_Scan, $conn=c,
			        $msg=fmt("Nmap UDP scan (-sU) from %s: %d closed UDP ports hit (previous notices: %d)", src, udp_count[src], udp_notices[src]),
			        $sub=fmt("last closed port %s:%s", context$id$resp_h, context$id$resp_p)]);
			udp_notices[src] += 1;
			udp_count[src] = 0;
			}
		}
	}
