let () = Random.self_init ()

let () = 
  for idx = 1 to 130 do
    Random.bits64 () |> Printf.printf "%3d %Li\n%!" idx
  done

let () =
  for idx = 1 to 50 do
    let input = Scanf.scanf "%Li\n" (fun x -> x) in
    if input <> (Random.bits64 ()) then
      let () = print_endline "Failed..." in
      exit 0
    else
      print_endline "Nice!"
  done

let () =
  let read_file filename =
    let ch = open_in_bin filename in
    let s = really_input_string ch (in_channel_length ch) in
    close_in ch;
    s
  in
  let () = print_endline "Flag is..." in
  read_file "./flag" |> print_string