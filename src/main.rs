#![warn(rust_2018_idioms)]
#![allow(dead_code)]

#[cfg(
    not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        all(target_feature = "aes", target_feature = "sse2")
    ))
)]
compile_error!("Needs to be compiled for a CPU that supports AES-NI!");

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use std::time::Instant;
use std::thread;
use std::sync::mpsc;

use num_cpus;

struct Schedule([__m128i; 20]);

fn load128(bytes: &[u8; 16]) -> __m128i {
    unsafe {
        _mm_loadu_si128(bytes.as_ptr() as *const __m128i)
    }
}

fn unload128(i: __m128i) -> [u8; 16] {
    let mut out: [u8; 16] = [0u8; 16];
    unsafe {
        _mm_store_si128(out.as_mut_ptr() as *mut __m128i, i);
    }
    return out;
}

macro_rules! aes128_key_expand {
    ($prev:expr, $rcon:literal) => {
        unsafe {
            let keygened: __m128i = _mm_aeskeygenassist_si128($prev, $rcon);
            let bcast: __m128i = _mm_shuffle_epi32(keygened, 0b11111111);
            let mut k = _mm_xor_si128($prev, _mm_slli_si128($prev, 4));
            k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
            k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
            _mm_xor_si128(k, bcast)
        }
    }
}

fn schedule(key: &[u8; 16]) -> Schedule {
    // todo: use uninitialized memory?
    let mut s: Schedule;
    unsafe {
        s = Schedule {0: [_mm_setzero_si128(); 20] };
    }
    s.0[0] = load128(key);
    s.0[1] = aes128_key_expand!(s.0[0], 0x01);
    s.0[2] = aes128_key_expand!(s.0[1], 0x02);
    s.0[3] = aes128_key_expand!(s.0[2], 0x04);
    s.0[4] = aes128_key_expand!(s.0[3], 0x08);
    s.0[5] = aes128_key_expand!(s.0[4], 0x10);
    s.0[6] = aes128_key_expand!(s.0[5], 0x20);
    s.0[7] = aes128_key_expand!(s.0[6], 0x40);
    s.0[8] = aes128_key_expand!(s.0[7], 0x80);
    s.0[9] = aes128_key_expand!(s.0[8], 0x1B);
    s.0[10] = aes128_key_expand!(s.0[9], 0x36);
    unsafe {
        s.0[11] = _mm_aesimc_si128(s.0[9]);
        s.0[12] = _mm_aesimc_si128(s.0[8]);
        s.0[13] = _mm_aesimc_si128(s.0[7]);
        s.0[14] = _mm_aesimc_si128(s.0[6]);
        s.0[15] = _mm_aesimc_si128(s.0[5]);
        s.0[16] = _mm_aesimc_si128(s.0[4]);
        s.0[17] = _mm_aesimc_si128(s.0[3]);
        s.0[18] = _mm_aesimc_si128(s.0[2]);
        s.0[19] = _mm_aesimc_si128(s.0[1]);
    }
    return s;
}

macro_rules! encm {
    ($s:expr, $w:expr) => {
        unsafe {
            $w = _mm_xor_si128($w, $s.0[0]);
            $w = _mm_aesenc_si128($w, $s.0[1]);
            $w = _mm_aesenc_si128($w, $s.0[2]);
            $w = _mm_aesenc_si128($w, $s.0[3]);
            $w = _mm_aesenc_si128($w, $s.0[4]);
            $w = _mm_aesenc_si128($w, $s.0[5]);
            $w = _mm_aesenc_si128($w, $s.0[6]);
            $w = _mm_aesenc_si128($w, $s.0[7]);
            $w = _mm_aesenc_si128($w, $s.0[8]);
            $w = _mm_aesenc_si128($w, $s.0[9]);
            $w = _mm_aesenclast_si128($w, $s.0[10]);
        }
    }
}

fn enc(s: &Schedule, mut w: __m128i) -> __m128i {
    encm!(s, w);
    return w;
}

macro_rules! decm {
    ($s:expr, $w:expr) => {
        unsafe {
            $w = _mm_xor_si128($w, $s.0[10]);
            $w = _mm_aesdec_si128($w, $s.0[11]);
            $w = _mm_aesdec_si128($w, $s.0[12]);
            $w = _mm_aesdec_si128($w, $s.0[13]);
            $w = _mm_aesdec_si128($w, $s.0[14]);
            $w = _mm_aesdec_si128($w, $s.0[15]);
            $w = _mm_aesdec_si128($w, $s.0[16]);
            $w = _mm_aesdec_si128($w, $s.0[17]);
            $w = _mm_aesdec_si128($w, $s.0[18]);
            $w = _mm_aesdec_si128($w, $s.0[19]);
            $w = _mm_aesdeclast_si128($w, $s.0[0]);
        }
    }
}

fn dec(s: &Schedule, mut w: __m128i) -> __m128i {
    decm!(s, w);
    return w;
}

fn smoke() {
    let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let plain: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
    let cipher: [u8; 16] = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
    let loaded = load128(&key);
    let unloaded = unload128(loaded);
    assert_eq!(key, unloaded);
    let s = schedule(&key);
    let p = load128(&plain);
    let pe = enc(&s, p);
    let plain_encrypted = unload128(pe);
    assert_eq!(plain_encrypted, cipher);
    let ped = dec(&s, pe);
    let encrypted_decrypted = unload128(ped);
    assert_eq!(encrypted_decrypted, plain);
}

fn simple_loop() {
    let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let plain: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
    let start = Instant::now();
    let s = schedule(&key);
    const SBS: usize = 16;
    let mut w = [load128(&plain); SBS];
    const ITERATIONS: usize = 10000000/SBS;
    for _ in 0..ITERATIONS {
        for i in 0..SBS {
            encm!(s, w[i]);
        }
    }
    for _ in 0..ITERATIONS {
        for i in 0..SBS {
            decm!(s, w[i]);
        }
    }
    let duration = start.elapsed();
    for i in 0..SBS {
        let encrypted_decrypted = unload128(w[i]);
        assert_eq!(encrypted_decrypted, plain);
    }
    println!("Ran {} iterations in {:?}", ITERATIONS * SBS, duration);
    let bytes = 16f64 * (ITERATIONS * SBS) as f64 * 2f64;
    let dur = duration.as_secs() as f64 
        + duration.subsec_nanos() as f64 * 1e-9;
    let mb = bytes / (1024f64 * 1024f64);
    println!("{:.1}MiB/s", mb/dur);
}

struct Report {
    iterations: usize,
    tid: usize
}

fn worker(tid: usize, ttx: mpsc::Sender<Report>) {
    let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let plain: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
    let s = schedule(&key);
    const SBS: usize = 16;
    let mut w = [load128(&plain); SBS];
    const ITERATIONS: usize = 100000000/SBS;
    let mut its: usize = 0;
    loop {
        for _ in 0..ITERATIONS {
            for i in 0..SBS {
                encm!(s, w[i]);
            }
        }
        for _ in 0..ITERATIONS {
            for i in 0..SBS {
                decm!(s, w[i]);
            }
        }
        for i in 0..SBS {
            let encrypted_decrypted = unload128(w[i]);
            assert_eq!(encrypted_decrypted, plain);
        }
        its += 2 * ITERATIONS * SBS;
        ttx.send(Report {iterations: its, tid: tid}).unwrap();
    }
}

fn worker_x(tid: usize, ttx: mpsc::Sender<Report>) {
    let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let plain: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
    let s = schedule(&key);
    const SBS: usize = 4;
    let mut w = [load128(&plain); SBS];
    const ITERATIONS: usize = 100000000/SBS;
    let mut its: usize = 0;
    loop {
        for _ in 0..ITERATIONS {
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_xor_si128(w[i], s.0[0]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesenc_si128(w[i], s.0[1]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesenc_si128(w[i], s.0[2]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesenc_si128(w[i], s.0[3]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesenc_si128(w[i], s.0[4]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesenc_si128(w[i], s.0[5]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesenc_si128(w[i], s.0[6]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesenc_si128(w[i], s.0[7]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesenc_si128(w[i], s.0[8]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesenc_si128(w[i], s.0[9]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesenclast_si128(w[i], s.0[10]);
                }
            }
        }
        for _ in 0..ITERATIONS {
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_xor_si128(w[i], s.0[10]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesdec_si128(w[i], s.0[11]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesdec_si128(w[i], s.0[12]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesdec_si128(w[i], s.0[13]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesdec_si128(w[i], s.0[14]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesdec_si128(w[i], s.0[15]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesdec_si128(w[i], s.0[16]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesdec_si128(w[i], s.0[17]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesdec_si128(w[i], s.0[18]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesdec_si128(w[i], s.0[19]);
                }
            }
            for i in 0..SBS {
                unsafe {
                    w[i] = _mm_aesdeclast_si128(w[i], s.0[0]);
                }
            }
        }
        for i in 0..SBS {
            let encrypted_decrypted = unload128(w[i]);
            assert_eq!(encrypted_decrypted, plain);
        }
        its += 2 * ITERATIONS * SBS;
        ttx.send(Report {iterations: its, tid: tid}).unwrap();
    }
}


fn threader() {
    let threads = num_cpus::get();
    let mut handles = Vec::new();
    let mut counts: Vec<usize> = Vec::new();
    let (tx, rx) = mpsc::channel::<Report>();
    
    for t in 0..threads {
        let tid = t;
        let ttx = mpsc::Sender::clone(&tx);
        handles.push(thread::spawn(move || {
            worker_x(tid, ttx);
        }));
        counts.push(0);
    }
    drop(tx);
    let start = Instant::now();
    for recieved in rx {
        let duration = start.elapsed();
        counts[recieved.tid] = recieved.iterations;
        let mut total_bytes: f64 = 0.0;
        for t in 0..threads {
            total_bytes += 16.0 * counts[t] as f64;
        }
        let dur = duration.as_secs() as f64 
                + duration.subsec_nanos() as f64 * 1e-9;
        let gib = total_bytes / (1024.0 * 1024.0 * 1024.0);
        println!("{:.2}GiB/s", gib/dur);
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

fn main() {
    smoke();
    simple_loop();
    threader();
}
