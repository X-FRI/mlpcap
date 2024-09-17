open Pcap

(* looking up suitable device *)
let (a) = pcap_lookupdev ();;

(* open it in promiscous mode *)
let openlive = pcap_open_live a 1500 1 0;;

Printf.printf "[+] opening interface %s ...\n" a ; flush_all ();;

(* open dump.out and return pcap_dumper xx *)
let xx = pcap_dump_open openlive "dump.out";;

(* callback function, dumps t to xx *)
let wrapdump (s:string) (h:pcap_pkthdr) (t:string) = pcap_dump_direct xx h t;;

for i = 0 to 10 do
	let x = pcap_loop openlive 1 wrapdump "" in flush_all () 
done;;

IFDEF HAVE_PCAP08 THEN
let _ = pcap_dump_flush xx END;;

let (_,aa) = pcap_stats openlive in
	Printf.printf "packets recv: %d\n" (aa.ps_recv);
	Printf.printf "packets drop: %d\n" (aa.ps_drop);
	Printf.printf "packets intf drop: %d\n" (aa.ps_ifdrop);;

let () = pcap_close openlive

