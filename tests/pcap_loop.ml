open Pcap

(* looking up suitable device *)
let (a) = pcap_lookupdev ();;

(* open it in promiscous mode *)
let openlive = pcap_open_live a 1500 1 0;;

Printf.printf "[+] opening interface %s ...\n" a ; flush_all ();;
	
(* callback ... *)
let callbkfun (s:string) (h:pcap_pkthdr) (t:string) =
	print_endline "[-] Entered callbkfun.\n";
	Printf.printf "timestamp: %u\n" (h.ts.tv_sec);
		let proto = (int_of_char (String.unsafe_get t 23)) in
	match proto with
	| 6 -> Printf.printf "-> TCP\n"
	| 1 -> Printf.printf "-> ICMP\n"
	| 17 -> Printf.printf "-> UDP\n"
	| _ -> Printf.printf "-> Unknown\n";;



let pcap_loop_test () =
	for i = 0 to 20 do
        begin
		let x = pcap_loop openlive 1 callbkfun "" in flush_all ()
        end
	done;;


let () = pcap_loop_test ();;

let () = pcap_close openlive


