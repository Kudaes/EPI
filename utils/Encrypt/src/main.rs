use std::{env, fs};
use std::fs::File;
use std::io::Read;

fn main() {
    unsafe
    {
        let args: Vec<String> = env::args().collect();
        let file = &args[1];
        let key = &args[2];

        // https://www.reddit.com/r/rust/comments/dekpl5/how_to_read_binary_data_from_a_file_into_a_vecu8/
        let mut f = File::open(file).expect("no file found");
        let metadata = fs::metadata(file).expect("unable to read metadata");
        let mut buffer = vec![0; metadata.len() as usize];
        f.read(&mut buffer).expect("buffer overflow");
        
        let mut view_ptr = buffer.as_ptr() as *mut u8;
        let key = format!("{}{}", key, "\0");
        let mut key_ptr = key.as_ptr();
        let mut xor_key: u8 = *key_ptr;
        key_ptr = key_ptr.add(1);
        while *key_ptr != '\0' as u8
        {
            xor_key = xor_key ^ *key_ptr;
            key_ptr = key_ptr.add(1);
        }
    
        let mut view_xor: Vec<u8> = vec![];
        for _i in 0..buffer.len()
        {
            view_xor.push(*view_ptr ^ xor_key);
            view_ptr = view_ptr.add(1);
        }

        fs::write(r"..\payload\payload.bin", view_xor).unwrap();

    }
    

}
