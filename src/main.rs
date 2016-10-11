extern crate rustc_serialize;

use rustc_serialize::hex::ToHex;
use rustc_serialize::base64::ToBase64;
use rustc_serialize::hex::FromHex;
use rustc_serialize::base64::STANDARD;
use std::str;
use std::fs::File;
use std::io::Read;
use std::cmp::Ordering::Equal;

fn get_score_char(character: char) -> u64 {
    let score = match character.to_uppercase().next().unwrap() {
        ' ' => 6000,
        'E' => 4452,
        'T' => 3305,
        'A' => 2865,
        'O' => 2723,
        'I' => 2697,
        'N' => 2578,
        'S' => 2321,
        'R' => 2238,
        'H' => 1801,
        'L' => 1450,
        'D' => 1360,
        'C' => 1192,
        'U' => 973,
        'M' => 895,
        'F' => 856,
        'P' => 761,
        'G' => 666,
        'W' => 597,
        'Y' => 593,
        'B' => 529,
        'V' => 375,
        'K' => 193,
        'X' => 84,
        'J' => 57,
        'Q' => 43,
        'Z' => 32,
        _ => 0,
    };
    if character.is_uppercase() {
        score
    } else {
        score * 3
    }
}


fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let mut dist = 0;
    for i in 0..a.len() {
        let r = a[i] ^ b[i];
        let mut two_pow = 1;
        for _ in 0..8 {
            if two_pow & r != 0 {
                dist += 1;
            }
            two_pow <<= 1;
        }
    }
    dist
}

fn xor_buffer_with_byte(input: &[u8], key: u8) -> Vec<u8> {
    let mut output: Vec<u8> = vec![0; input.len()];
    for (i, input_byte) in input.into_iter().enumerate() {
        output[i] = key ^ input_byte
    }
    return output
}

fn transpose(input: &[u8], len: usize) -> Vec<Vec<u8>> {
    let mut output = Vec::new();
    for _ in 0..len {
        output.push(Vec::<u8>::new());
    }
    for i in 0..input.len() {
        output[i % len].push(input[i]);
    }
    output
}

fn untranspose(input: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut output = Vec::new();
    let block_count = input.len();
    let mut i = 0;
    loop {
        output.push(input[i % block_count][i / block_count]);
        i += 1;
        if i / block_count >= input[i % block_count].len() {
            break;
        }
    }
    return output;
}

fn get_score_str(str: &str) -> u64 {
    let mut score: u64 = 0;
    for c in str.chars() {
        score += get_score_char(c);
    }
    score
}

fn break_repeating_key_xor_with_keysize(cyphertext: &[u8], keysize: usize) -> Vec<u8> {
    //println!("break_repeating_key_xor_with_keysize {}", keysize);
    let blocks = transpose(cyphertext, keysize);
    let mut key = Vec::<u8>::new();
    for block in blocks {
        let (block_key, _, _) = break_xor(&block).expect("no solution");
        key.push(block_key);
    }
    key
}

fn score_repeating_key_xor_keysize(plaintext: &[u8], keysize: usize) -> f32 {
    let d1 = hamming_distance(&plaintext[0..keysize], &plaintext[keysize..keysize * 2]);

    let d2 = hamming_distance(&plaintext[0..keysize], &plaintext[keysize * 2..keysize * 3]);
    let d3 = hamming_distance(&plaintext[keysize..keysize * 2], &plaintext[keysize * 2..keysize * 3]);

    let d4 = hamming_distance(&plaintext[0..keysize], &plaintext[keysize * 3..keysize * 4]);
    let d5 = hamming_distance(&plaintext[keysize..keysize * 2], &plaintext[keysize * 3..keysize * 4]);
    let d6 = hamming_distance(&plaintext[keysize * 2..keysize * 3], &plaintext[keysize * 3..keysize * 4]);

    return ((d1 + d2 + d3 + d4 + d5 + d6) as f32) / ((keysize) as f32);
}


fn break_repeating_key_xor(cyphertext: &[u8]) -> Vec<u8> {
    let mut candidate_lengths: Vec<(usize, f32)> = Vec::new();
    for i in 1..40 {
        let score = score_repeating_key_xor_keysize(cyphertext, i);
        candidate_lengths.push((i, score));
    }
    candidate_lengths.sort_by(|&(_, s1), &(_, s2)| s1.partial_cmp(&s2).unwrap_or(Equal));

    let (candidate_len, _) = candidate_lengths[0];
    let key = break_repeating_key_xor_with_keysize(cyphertext, candidate_len);
    return key;
}

fn encrypt_repeating_key_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = vec![0; plaintext.len()];
    for (i, input_byte) in plaintext.into_iter().enumerate() {
        output[i] = input_byte ^ key[i % key.len()]
    }
    output
}

fn break_xor(input: &[u8]) -> Result<(u8, u64, String), ()> {
    let mut best_score = 0;
    let mut best = String::new();
    let mut best_key = 0;
    let mut found = false;
    for i in 0..255 {
        let output = xor_buffer_with_byte(&input, i);
        if let Ok(string) = String::from_utf8(output) {
            let score = get_score_str(&string);
            if score > best_score {
                best_score = score;
                best = string;
                best_key = i;
                found = true;
            }
        }
    }
    if found {
        return Ok((best_key, best_score, best))
    } else {
        return Err(())
    }
}


fn challenge_5(input: &str, key: &[u8]) -> String {
    let input = input.as_bytes();
    encrypt_repeating_key_xor(&input, &key).to_hex()
}

fn challenge_4() -> String {
    let mut file = File::open("data\\challenge_4").expect("unable to load file");
    let mut s = String::new();
    file.read_to_string(&mut s).expect("Error reading bytes from file");
    let line_iter = s.split("\n");

    let mut best_score: u64 = 0;
    let mut best_plaintext = String::new();
    for line in line_iter {
        let line_bytes = line.trim().from_hex().expect("from hex error");
        match break_xor(&line_bytes) {
            Ok((_, score, plaintext)) => {
                if score > best_score {
                    best_score = score;
                    best_plaintext = plaintext;
                }
            },
            _ => {}
        }
    }
    best_plaintext
}

fn challenge_3(ciphertext: &str) -> String {
    let input: Vec<u8> = ciphertext.from_hex().expect("from hex error");
    let (_, _, plaintext) = break_xor(&input).expect("No valid UTF8 decryptions");
    plaintext
}

fn challenge_2(input: &str, key: &str) -> String {
    let input: Vec<u8> = input.from_hex().expect("from hex error");
    let key: Vec<u8> = key.from_hex().expect("from hex error");

    let mut output: Vec<u8> = vec![0; input.len()];
    for (i, input_byte) in input.into_iter().enumerate() {
        output[i] = key[i] ^ input_byte
    }
    output.to_hex()
}

fn challenge_1(hex_encoded: &str) -> String {
    let bytes = hex_encoded.from_hex().expect("could not decode string");
    bytes.to_base64(STANDARD).to_string()
}


#[cfg(test)]
mod tests {
    use super::hamming_distance;
    use super::transpose;
    use super::untranspose;
    use super::challenge_1;
    use super::challenge_2;
    use super::challenge_3;
    use super::challenge_4;
    use super::challenge_5;
    use std::fs::File;
    use std::io::Read;
    use rustc_serialize::base64::FromBase64;
    use super::break_repeating_key_xor;


    #[test]
    fn test_transpose() {
        let transposed = transpose(&vec![0,1,2,3,4,5,6], 3);
        assert_eq!(transposed[0], vec![0,3,6]);
        assert_eq!(transposed[1], vec![1,4]);
        assert_eq!(transposed[2], vec![2,5]);
    }

    #[test]
    fn test_untranspose() {
        let transposed = &vec![vec![0,3,6], vec![1,4], vec![2, 5]];
        assert_eq!(untranspose(transposed), vec![0,1,2,3,4,5,6])
    }

    #[test]
    fn test_challenge_1() {
        let hex_encoded = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(expected, challenge_1(hex_encoded));
    }

    #[test]
    fn test_challenge_2() {
        let reference_input = "1c0111001f010100061a024b53535009181c";
        let reference_key = "686974207468652062756c6c277320657965";
        let reference_output = "746865206b696420646f6e277420706c6179";

        let output = challenge_2(reference_input, reference_key);
        assert_eq!(reference_output, output);
    }

    #[test]
    fn test_challenge_3() {
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected = "Cooking MC's like a pound of bacon";
        let out = challenge_3(ciphertext);
        assert_eq!(expected, out);
    }

    #[test]
    fn test_challenge_4() {
        assert_eq!(challenge_4(), "Now that the party is jumping\n");
    }

    #[test]
    fn test_challenge_5() {
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

        let expected_output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d62\
    3d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630\
    c692b20283165286326302e27282f";


        assert_eq!(expected_output, challenge_5(input, &vec![73, 67, 69]));
    }

    #[test]
    fn test_hamming_distance() {
        let test_a = "this is a test".to_string();
        let test_b = "wokka wokka!!!".to_string();
        let d = hamming_distance(&test_a.as_bytes(), &test_b.as_bytes());
        assert!(d == 37)
    }

    #[test]
    fn test_challenge_6() {
        let mut file = File::open("data\\challenge_6").expect("unable to load file");
        let mut s = String::new();
        file.read_to_string(&mut s).expect("Error reading bytes from file");
        let ciphertext = s.from_base64().expect("Error decodeing base 64");
        assert_eq!("Terminator X: Bring the noise",
        String::from_utf8(break_repeating_key_xor(&ciphertext)).expect("failed to decode key into utf8"));
    }
}

