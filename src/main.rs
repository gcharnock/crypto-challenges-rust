extern crate rustc_serialize;

use rustc_serialize::hex::ToHex;
use rustc_serialize::base64::ToBase64;
use rustc_serialize::hex::FromHex;
use rustc_serialize::base64::STANDARD;
use std::str;
use std::fs::File;
use std::io::Read;

fn get_score_char(character: char) -> u64 {
    return match character.to_uppercase().next().unwrap() {
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
    }
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let mut dist = 0;
    for i in 0..a.len() {
        let r = a[i] ^ b[i];
        let mut two_pow = 1;
        for _ in 0..8 {
            if two_pow & r != 0 {
                dist+=1;
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

fn transpose(input: &[u8], len: u8) -> Vec<Vec<u8>> {
    let mut output = Vec::new();
    for i in 0..len {
        output.push(Vec::new());
    }
    output
}

fn get_score_str(str: &str) -> u64 {
    let mut score: u64 = 0;
    for c in str.chars() {
        score += get_score_char(c);
    }
    score
}

fn encrypt_repeating_key_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = vec![0; plaintext.len()];
    for (i, input_byte) in plaintext.into_iter().enumerate() {
        output[i] = input_byte ^ key[i % key.len()]
    }
    output
}

fn decrypt_xor(input: &[u8]) -> Result<(u8, u64, String), ()> {
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

fn challenge_6() {
    let test_a = "this is a test".to_string();
    let test_b = "wokka wokka!!!".to_string();
    let d = hamming_distance(&test_a.as_bytes(), &test_b.as_bytes());
    println!("hamming distance between sample strings was {}", d);
}

fn challenge_5() {
    let input = "Burning 'em, if you ain't quick and nimble\n\
    I go crazy when I hear a cymbal".to_string().as_bytes().to_vec();
    let key = vec![73, 67, 69];
    let expected_output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d62\
    3d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630\
    c692b20283165286326302e27282f".from_hex().expect("error decoding hex");

    let output = encrypt_repeating_key_xor(&input, &key);
    println!("output = {}, passed = {}", output.to_hex(), output == expected_output)
}

fn challenge_4() {
    let mut file = File::open("data\\challenge_4").expect("unable to load file");
    let mut s = String::new();
    file.read_to_string(&mut s).expect("Error reading bytes from file");
    let line_iter = s.split("\n");

    let mut best_score: u64 = 0;
    let mut best_plaintext = String::new();
    for line in line_iter {
        let line_bytes = line.trim().from_hex().expect("from hex error");
        match decrypt_xor(&line_bytes) {
            Ok((_, score, plaintext)) => {
                if score > best_score {
                    best_score = score;
                    best_plaintext = plaintext;
                }
            },
            _ => {}
        }
    }
    println!("best string was \"{}\" and score was {}", best_plaintext, best_score)
}

fn challenge_3() {
    let input_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let input: Vec<u8> = input_hex.from_hex().expect("from hex error");
    let (key, score, plaintext) = decrypt_xor(&input).expect("No valid UTF8 decryptions");
    println!("best string was \"{}\" and score was {}, key was {}", plaintext, score, key)
}

fn challenge_2() {
    let reference_input = "1c0111001f010100061a024b53535009181c";
    let reference_key = "686974207468652062756c6c277320657965";
    let reference_output = "746865206b696420646f6e277420706c6179";

    let input: Vec<u8> = reference_input.from_hex().expect("from hex error");
    let key: Vec<u8> = reference_key.from_hex().expect("from hex error");

    let mut output: Vec<u8> = vec![0; input.len()];
    for (i, input_byte) in input.into_iter().enumerate() {
        output[i] = key[i] ^ input_byte
    }
    let output_str = output.to_hex();
    println!("output was was {}, passed = {}", output_str, output_str == reference_output)
}

fn challenge_1() {
    let hex_encoded = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let bytes = hex_encoded.from_hex().expect("could not decode string");
    let base64_encoded = bytes.to_base64(STANDARD);
    println!("base64 was {}, expected = {}", base64_encoded, base64_encoded == expected)
}

fn main() {
    challenge_1();
    challenge_2();
    challenge_3();
    challenge_4();
    challenge_5();
    challenge_6();
}
