open Pcap

(* looking up suitable device *)
let (a) = pcap_lookupdev ();;

let openlive = pcap_open_offline "dump.out";;

let minor = pcap_minor_version openlive;;
let major = pcap_major_version openlive;;

Printf.printf "Running with pcap %d.%d\n" major minor;;

let (_,aa) = pcap_stats openlive in
        Printf.printf "packets recv: %d\n" (aa.ps_recv);
        Printf.printf "packets drop: %d\n" (aa.ps_drop);
        Printf.printf "packets intf drop: %d\n" (aa.ps_ifdrop);;

(*let () = pcap_dump_close xx*)
let () = pcap_close openlive

