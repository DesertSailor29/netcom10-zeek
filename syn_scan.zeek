redef enum Notice::Type += { SYN_Scan };

global syn_count: table[addr] of count &default=0;
global syn_notices: table[addr] of count &default=0;

event connection_SYN_packet(c: connection, pkt: SYN_packet)
	{
	if ( pkt$win_size == 1024 && pkt$win_scale == -1 && ! pkt$SACK_OK && ! pkt?$TSval )
		{
		local src = c$id$orig_h;
		syn_count[src] += 1;

		if ( syn_count[src] == 1000 )
			{
			NOTICE([$note=SYN_Scan, $conn=c,
			        $msg=fmt("Nmap SYN scan (-sS) from %s: %d half-open probes (previous notices: %d)", src, syn_count[src], syn_notices[src]),
			        $sub=fmt("last probe to %s:%s", c$id$resp_h, c$id$resp_p)]);
			syn_notices[src] += 1;
			syn_count[src] = 0;
			}
		}
	}
