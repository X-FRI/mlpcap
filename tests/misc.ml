open Pcap

(* looking up suitable device *)
let (a) = pcap_lookupdev ();;

let (one,two,three) = pcap_lookupnet a;;
Printf.printf "netmask ptr: %x\n" three;;

(* open it in promiscous mode *)
let openlive = pcap_open_live a 1500 1 0;;

IFDEF HAVE_PCAP08 THEN let vers = pcap_lib_version () in
        Printf.printf "using %s\n" vers END;;

(* dltbuf is an int array containing the supported datalinks *)
IFDEF HAVE_PCAP08 THEN let (ret,dltbuf) = pcap_list_datalinks openlive in
	Printf.printf "datalinks supported on %s:\n" a;
	Array.iter (fun x -> 
		Printf.printf "\t%s\n" (pcap_datalink_val_to_name x))
		dltbuf END;;

IFDEF HAVE_PCAP08 THEN let ret = pcap_datalink openlive in
	Printf.printf "my current datalink is %s\n" 
		(pcap_datalink_val_to_description ret) END;;

(* in nonblocking mode? *)
let r = pcap_getnonblock openlive in
        Printf.printf "nonblocking mode is %d\n" r;;

let () = pcap_close openlive

