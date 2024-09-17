open Pcap

let ethdevs = pcap_findalldevs ();;

Printf.printf "Available interfaces:\n";;
for i = 0 to (Array.length ethdevs)-1 do
        let aa = Printf.printf "%s\n" ethdevs.(i).name in flush_all ()
done;;

