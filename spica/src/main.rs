use aya::{include_bytes_aligned, Bpf};
use aya::programs::TracePoint;
use aya::maps::HashMap as AyaHashMap;
use spica_common::ProcessInfo;
use std::{fs, thread, time::{Duration, Instant}};
use std::collections::{HashMap, HashSet};

const TICK_RATE: u64 = 1; //check every 1 second
const SUSPECT_THRESHOLD: u64 = 2; //register potential hidden process after 2 seconds

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/spica"))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/spica"))?;

    let program: &mut TracePoint = bpf.program_mut("spica_monitor").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;

    println!("I'm going to sing, so shine bright, SPiCa...");

    let mut suspects: HashMap<u32, Instant> = HashMap::new();

    loop {
        let loop_start = Instant::now();

        let mut user_pids: HashSet<u32> = HashSet::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    user_pids.insert(pid);
                }
            }
        }

        let mut kernel_orbit: AyaHashMap<_, u32, ProcessInfo> = AyaHashMap::try_from(bpf.map_mut("KERNEL_ORBIT").unwrap())?;

        let keys: Vec<u32> = kernel_orbit.keys().collect::<Result<_, _>>()?;

        for pid in keys {
            let info = kernel_orbit.get(&pid, 0)?; // 0 = flag

            let k_name = std::str::from_utf8(&info.comm)
                .unwrap_or("???")
                .trim_matches(char::from(0));

            if !user_pids.contains(&info.tgid) {

                //poke test to check if process still alive

                let is_alive = unsafe { libc::kill(pid as i32, 0) == 0 };

                if !is_alive {
                    let _ = kernel_orbit.remove(&pid);
                    
                    suspects.remove(&pid);
                    continue;
                }

                match suspects.get(&pid) {

                    //Detect hidden processes
                    Some(first_seen) => {
                        if first_seen.elapsed() > Duration::from_secs(SUSPECT_THRESHOLD) {
                            println!("[ROOTKIT DETECTED] PID: {} | NAME: {} | HIDDEN FOR: {:?}", pid, k_name, first_seen.elapsed());
                        }
                    },
                    None => {
                        suspects.insert(pid, Instant::now());
                    }
                }
            } 

            else {

                 //clears suspected processes in case of a race condition
                if suspects.contains_key(&pid) {
                    suspects.remove(&pid);
                }
            }
        }

        suspects.retain(|pid, _| user_pids.contains(pid) || kernel_orbit.get(pid, 0).is_ok());

        let elapsed = loop_start.elapsed();
        if elapsed < Duration::from_secs(TICK_RATE) {
            thread::sleep(Duration::from_secs(TICK_RATE) - elapsed);
        }
    }
}
