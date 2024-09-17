open Pcap

(* looking up suitable device *)
let (a) = pcap_lookupdev ();;

(* open it in promiscous mode *)
let openlive = pcap_open_live a 1500 1 0;;

Printf.printf "[+] opening interface %s ...\n" a ; flush_all ();;

let global_data = ref "";;
let global_pkthdr = ref None;;

(* pcap dispatch callback, set reference to t which contains the packet  *)
let dbkfun (s:string) (h:pcap_pkthdr) (t:string) =
	global_pkthdr := Some h;
	global_data := t;;

(* example implementation of pcap_next, returning the next packet *)
let pcap_next ol =
	let _ = pcap_dispatch ol 1 dbkfun "" in !global_data


let pcap_next_ex ol = 
	let ret = pcap_dispatch ol 1 dbkfun "" in (ret, !global_data, !global_pkthdr)


let main () =
	(*while true do*)
		let data = pcap_next openlive in 
		flush_all ()
			(* do something, process the data *)
	(*done;;*)


let () = main ();;

(* print statistics *)
let (_,aa) = pcap_stats openlive in
	Printf.printf "packets recv: %d\n" (aa.ps_recv);
	Printf.printf "packets drop: %d\n" (aa.ps_drop);
	Printf.printf "packets intf drop: %d\n" (aa.ps_ifdrop);;

let () = pcap_close openlive


