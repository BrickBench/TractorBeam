extern crate stopwatch;
extern crate windows;
extern crate windows_sys;
extern crate core;
extern crate sha3;
extern crate openssl;

use stopwatch::{Stopwatch};
use openssl::rsa::*;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::Foundation::{HANDLE, CHAR, STILL_ACTIVE, CloseHandle};
use windows::Win32::System::Diagnostics::ToolHelp::{PROCESSENTRY32, CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, Process32First, Process32Next};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS, GetExitCodeProcess};
use std::iter::FromIterator;
use core::{mem, time};
use std::{thread, fs};
use std::ops::Deref;
use std::borrow::{Borrow, BorrowMut};
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use sha3::{Digest, Sha3_256};

pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32
}

enum EventKind {
    GameOpen(HANDLE),
    GameClose(HANDLE),
    MapChange(String),
    Position(Vec3, Vec3),
    Verification([u8; 32])
}

enum State {
    Running(HANDLE),
    Stopped,
}

struct Event {
    kind: EventKind,
    millis: i64
}

unsafe fn read_vec3(addr: u64, handle: HANDLE) -> Vec3 {
    let mut vec: Vec3 = Vec3{ x: 0.0, y: 0.0, z: 0.0 };
    let mut read: usize = 0;

    ReadProcessMemory(handle.0 as *mut c_void, addr as *mut c_void,
                       &mut vec as *mut _ as *mut c_void, 12, &mut read);
    return vec;
}

unsafe fn read_int(addr: u64, handle: HANDLE) -> u32 {
    let mut int: u32 = 0;
    let mut read: usize = 0;

    ReadProcessMemory(handle.0 as *mut c_void, addr as *mut c_void,
                      &mut int as *mut _ as *mut c_void, 4, &mut read);
    return int;
}

unsafe fn gen_hash(events: &[Event]) -> EventKind{
    let mut hasher = Sha3_256::new();

    let mut hash_block: Vec<u8> = Vec::new();

    events.iter().for_each(|item| {
        match &item.kind {
            EventKind::GameOpen(pid) => {
                hash_block.extend_from_slice(pid.0.to_be_bytes().as_slice())
            },
            EventKind::GameClose(pid) => {
                hash_block.extend_from_slice(pid.0.to_be_bytes().as_slice())
            }
            EventKind::MapChange(name) => {
                hash_block.extend_from_slice(name.as_bytes())
            }
            EventKind::Position(p1, p2) => {
                hash_block.extend_from_slice((p1.x + p1.y - p1.z + p2.x - p2.y + p2.z).to_be_bytes().as_slice())
            },
            EventKind::Verification(vec) => {
                hash_block.extend_from_slice(vec.as_slice())
            }
        }
    });

    hasher.update(hash_block);

    return EventKind::Verification(hasher.finalize().into());
}

fn main() {
    let watch = Stopwatch::start_new();
    let mut events: Vec<Event> = Vec::new();
    let mut state = State::Stopped;

    loop {
        match state {
            State::Running(handle) => unsafe {
                let mut exit_code: u32 = 0;
                GetExitCodeProcess(handle, &mut exit_code);

                if exit_code != STILL_ACTIVE.0 as u32 {
                    state = State::Stopped;

                    events.push(Event {kind: EventKind::GameClose(handle), millis: watch.elapsed_ms()});
                    CloseHandle(handle);
                } else {
                    let player1_addr = read_int(0x93d810, handle);
                    let player2_addr = read_int(0x93d814, handle);

                    let player1_pos = read_vec3((player1_addr + 0x5c) as u64, handle);
                    let player2_pos = read_vec3((player2_addr + 0x5c) as u64, handle);
                    events.push(Event {kind: EventKind::Position(player1_pos, player2_pos), millis: watch.elapsed_ms()});

                    if events.len() % 20 == 0 {
                        events.push(Event{ millis: watch.elapsed_ms(), kind: gen_hash(&events[events.len() - 20..events.len()])});
                    }
                }
            }
            State::Stopped => unsafe {
                let mut proc_entry = PROCESSENTRY32::default();
                proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

                if Process32First(snapshot, &mut proc_entry).as_bool() {
                    while Process32Next(snapshot, &mut proc_entry).as_bool() {
                        let good_bytes = mem::transmute::<[CHAR; 260], [u8; 260]>(proc_entry.szExeFile);
                        let good_str = String::from_utf8_lossy(&good_bytes).to_string();
                        if good_str.starts_with("LEGOStarWarsSaga.exe") {
                            let process = OpenProcess(PROCESS_ALL_ACCESS, false, proc_entry.th32ProcessID);
                            state = State::Running(process);

                            events.push(Event {kind: EventKind::GameOpen(process), millis: watch.elapsed_ms()});

                            break;
                        }
                    }
                }
            }
        }

        let ten_millis = time::Duration::from_millis(50);
        thread::sleep(ten_millis);

        if watch.elapsed().as_secs() > 60 {
            break;
        }
    }

    let mut out_str = String::new();

    events.iter().for_each(|item| {
        out_str.push_str(&*item.millis.to_string());
        out_str.push_str(";");
        out_str.push_str(match &item.kind {
            EventKind::GameOpen(pid) => format!("OPEN {}", pid.0),
            EventKind::GameClose(pid) => format!("CLOSE {}", pid.0),
            EventKind::MapChange(_) => "MapChange".to_string(),
            EventKind::Position(pos1, pos2) => format!("POS {0},{1},{2} {3},{4},{5}", pos1.x, pos1.y, pos1.z, pos2.x, pos2.y, pos2.z),
            EventKind::Verification(v) => format!("VERIFY {:X?}", v.as_slice()),
        }.borrow());
        out_str.push_str(";\n");
    });

    let pub_key = "TEST";

    let rsa = Rsa::public_key_from_pem(pub_key.as_bytes()).unwrap();
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    let _ = rsa.public_encrypt(out_str.as_bytes(), &mut buf, Padding::PKCS1).unwrap();

    fs::write("test.out", buf).expect("Unable to write file");
}
