
pub fn register_resource(numa_nodes: u32, cpusets: &str) -> Result<(), String> {
    let contents = match fs::read_to_string("test.txt") {
        Ok(file_contents) => file_contents,
        Err(e) => return Err(e.to_string()),
    };
    let mut registered = false;
    for line in contents.lines() {
        if line.to_lowercase().contains("agent") {
            registered = true;
            println!("already registered");
            break;
        }
    }
    if !registered {
        if let Ok(data) = gen_resource_info(numa_nodes, cpusets) {
            if let Err(e) = fs::write("info", data) {
                return Err(e.to_string());
            }
        } else {
            return Err("aaa".to_string());
        }
        match Command::new("sh").arg("-c").arg("ls -l").status() {
            Ok(result) => {
                if result.success() {
                    println!("registered success")
                } else {
                    println!("registered failed")
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

pub fn gen_resource_info(numa_nodes: u32, cpusets: &str) -> Result<String, io::Error> {
    let MEM_LIMIT = 256;
    let mut mem: Vec<String> = Vec::new();
    let mut cpus: Vec<u32> = Vec::new();
    let per_node = MEM_LIMIT / numa_nodes;
    for i in 0..numa_nodes {
        mem.push(format!("node{}: {}", i, per_node))
    }
    let cpusets: Vec<&str> = cpusets.split(",").collect();
    for cpuset in cpusets {
        let cpu: Vec<&str> = cpuset.split("-").collect();
        if cpu.len() == 1 {
            cpus.push(cpu[0].parse().unwrap());
        } else {
            let left: u32 = cpu[0].parse().unwrap();
            let right: u32 = cpu[1].parse().unwrap();
            for i in left..=right {
                cpus.push(i);
            }
        }
    }
    cpus.sort();
    println!("{:?}", mem);
    println!("{:?}", cpus);
    Ok(String::from("hhhh"))
}
