redef enum Notice::Type += { Connect_Scan };

global connect_count: table[addr] of count &default=0;
global connect_notices: table[addr] of count &default=0;

event connection_state_remove(c: connection)
	{
	if ( c$history == "ShAR" && c$orig$size == 0 && c$resp$size == 0 )
		{
		local src = c$id$orig_h;
		connect_count[src] += 1;

		if ( connect_count[src] == 50 )
			{
			NOTICE([$note=Connect_Scan, $conn=c,
			        $msg=fmt("Nmap connect scan (-sT) from %s: %d connect-then-reset connections (previous notices: %d)", src, connect_count[src], connect_notices[src]),
			        $sub=fmt("last open port %s:%s", c$id$resp_h, c$id$resp_p)]);
			connect_notices[src] += 1;
			connect_count[src] = 0;
			}
		}
	}
