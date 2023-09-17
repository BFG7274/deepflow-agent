/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use std::{fs, io, process, thread};

use super::Error;
use crate::config::handler::EnvironmentAccess;

use arc_swap::access::Access;
use cgroups_rs::cgroup_builder::*;
use cgroups_rs::*;
use log::{info, warn};
use nix::sys::utsname::uname;
use public::consts::{DEFAULT_CPU_CFS_PERIOD_US, PROCESS_NAME};

pub struct Cgroups {
    config: EnvironmentAccess,
    thread: Mutex<Option<JoinHandle<()>>>,
    running: Arc<(Mutex<bool>, Condvar)>,
    cgroup: Cgroup,
    mount_path: String,
    is_v2: bool,
    cpuset_dir: String,
}

const CHECK_INTERVAL: Duration = Duration::from_secs(1);
const CPUSET_DIR: [&str; 4] = ["", "", "", ""];

impl Cgroups {
    /// 创建cgroup hierarchy
    pub fn new(pid: u64, config: EnvironmentAccess) -> Result<Self, Error> {
        let contents = match fs::read_to_string("/proc/filesystems") {
            Ok(file_contents) => file_contents,
            Err(e) => {
                return Err(Error::CgroupsNotSupported(e.to_string()));
            }
        };
        let mut cgroup_supported = false;
        for line in contents.lines() {
            // 检查系统是否支持cgroup
            if line.to_lowercase().contains("cgroup") {
                cgroup_supported = true;
                break;
            }
        }
        if !cgroup_supported {
            return Err(Error::CgroupsNotSupported(format!(
                "cgroups v1 or v2 is not found."
            )));
        }
        let hier = hierarchies::auto();
        let is_v2 = hier.v2();
        let cg: Cgroup = CgroupBuilder::new(PROCESS_NAME).build(hier);
        let cpus: &cpu::CpuController = match cg.controller_of() {
            Some(controller) => controller,
            None => {
                return Err(Error::CpuControllerSetFailed(format!(
                    "maybe cgroups is not installed"
                )));
            }
        };
        let mem: &memory::MemController = match cg.controller_of() {
            Some(controller) => controller,
            None => {
                return Err(Error::MemControllerSetFailed(format!(
                    "maybe cgroups is not installed"
                )));
            }
        };
        let cpuset: &cpuset::CpuSetController = match cg.controller_of() {
            Some(controller) => controller,
            None => {
                return Err(Error::CpusetControllerSetFailed(format!(
                    "maybe cgroups is not installed"
                )));
            }
        };
        let mut cpuset_dir = String::new();
        for dir in CPUSET_DIR {
            if Path::new(dir).exists() {
                cpuset_dir = dir.to_string();
                break;
            }
        }
        if cpuset_dir.len() == 0 {
            return Err(Error::GetCgroupFailed("empty".to_string()));
        }
        if !is_cgroup_procs_writable() {
            // In kernel versions before Linux 3.0, we use add_task method, write thread id to the tasks file
            if let Err(e) = cpus.add_task(&CgroupPid::from(pid)) {
                // fixme:All thread IDs belonging to this process need to be recorded to this file
                return Err(Error::CpuControllerSetFailed(e.to_string()));
            }
            if let Err(e) = mem.add_task(&CgroupPid::from(pid)) {
                return Err(Error::MemControllerSetFailed(e.to_string()));
            }
            if let Err(e) = cpuset.add_task(&CgroupPid::from(pid)) {
                return Err(Error::CpusetControllerSetFailed(e.to_string()));
            }
        } else {
            // In versions after Linux 3.0, we call the add_task_by_tgid method, which will
            // write the pid to the cgroup.procs file, so cgroups will automatically synchronize
            // the tasks file. Refer to: https://wudaijun.com/2018/10/linux-cgroup/
            if let Err(e) = cpus.add_task_by_tgid(&CgroupPid::from(pid)) {
                return Err(Error::CpuControllerSetFailed(e.to_string()));
            }
            if let Err(e) = mem.add_task_by_tgid(&CgroupPid::from(pid)) {
                return Err(Error::MemControllerSetFailed(e.to_string()));
            }
            if let Err(e) = cpuset.add_task_by_tgid(&CgroupPid::from(pid)) {
                return Err(Error::CpusetControllerSetFailed(e.to_string()));
            }
        }
        let mem_stat = mem.memory_stat();
        println!("{:?}", mem_stat.numa_stat.total_pages_per_node.len());
        Ok(Cgroups {
            config,
            thread: Mutex::new(None),
            running: Arc::new((Mutex::new(false), Condvar::new())),
            cgroup: cg,
            mount_path: hierarchies::auto().root().to_str().unwrap().to_string(),
            is_v2,
            cpuset_dir,
        })
    }

    pub fn get_mount_path(&self) -> String {
        self.mount_path.clone()
    }

    pub fn is_v2(&self) -> bool {
        self.is_v2
    }

    pub fn start(&self) {
        {
            let (started, _) = &*self.running;
            let mut started = started.lock().unwrap();
            if *started {
                return;
            }
            *started = true;
        }

        let environment_config = self.config.clone();
        let running = self.running.clone();
        let mut last_cpu = 0;
        let mut last_memory = 0;
        let cgroup = self.cgroup.clone();
        let mut last_cpuset_cpus = String::new();
        let mut last_cpuset_mems = String::new();
        let thread = thread::Builder::new()
            .name("cgroups-controller".to_owned())
            .spawn(move || {
                loop {
                    let environment = environment_config.load();
                    let max_cpus = environment.max_cpus;
                    let max_memory = environment.max_memory;
                    let [max_cpuset_cpus, max_cpuset_mems] =
                        match get_cgroup_cpuset(&self.cpuset_dir) {
                            Ok(data) => data,
                            Err(e) => {
                                warn!("get cpuset data failed, {}, deepflow-agent restart...", e);
                                thread::sleep(Duration::from_secs(1));
                                process::exit(1);
                            }
                        };
                    if max_cpus != last_cpu
                        || max_memory != last_memory
                        || max_cpuset_cpus != last_cpuset_cpus
                        || max_cpuset_mems != last_cpuset_mems
                    {
                        if let Err(e) = Self::apply(
                            cgroup.clone(),
                            max_cpus,
                            max_memory,
                            &max_cpuset_cpus,
                            &max_cpuset_mems,
                        ) {
                            warn!(
                                "apply cgroups resource failed, {}, deepflow-agent restart...",
                                e
                            );
                            thread::sleep(Duration::from_secs(1));
                            process::exit(1);
                        }
                    }
                    last_cpu = max_cpus;
                    last_memory = max_memory;
                    last_cpuset_cpus = max_cpuset_cpus;
                    last_cpuset_mems = max_cpuset_mems;

                    let (running, timer) = &*running;
                    let mut running = running.lock().unwrap();
                    if !*running {
                        break;
                    }
                    running = timer.wait_timeout(running, CHECK_INTERVAL).unwrap().0;
                    if !*running {
                        break;
                    }
                }
                info!("cgroups controller exited");
            })
            .unwrap();

        self.thread.lock().unwrap().replace(thread);
        info!("cgroups controller started");
    }

    /// 更改资源限制
    pub fn apply(
        cgroup: Cgroup,
        max_cpus: u32,
        max_memory: u64,
        max_cpuset_cpus: &str,
        max_cpuset_mems: &str,
    ) -> Result<(), Error> {
        let mut resources = Resources::default();
        let cpu_quota = max_cpus * DEFAULT_CPU_CFS_PERIOD_US;
        let cpu_resources = CpuResources {
            quota: Some(cpu_quota as i64),
            period: Some(DEFAULT_CPU_CFS_PERIOD_US as u64),
            ..Default::default()
        };
        resources.cpu = cpu_resources;

        let memory_resources = MemoryResources {
            memory_hard_limit: Some(max_memory as i64),
            ..Default::default()
        };
        resources.memory = memory_resources;
        if let Err(e) = cgroup.apply(&resources) {
            return Err(Error::ApplyResourcesFailed(e.to_string()));
        }

        let cpuset: &cpuset::CpuSetController = match cgroup.controller_of() {
            Some(controller) => controller,
            None => {
                return Err(Error::CpusetControllerSetFailed(format!(
                    "maybe cgroups is not installed"
                )));
            }
        };
        if let Err(e) = cpuset.set_mems(max_cpuset_mems) {
            return Err(Error::CpusetMemSetFailed(e.to_string()));
        }
        if let Err(e) = cpuset.set_cpus(max_cpuset_cpus) {
            return Err(Error::CpusetMemSetFailed(e.to_string()));
        }
        Ok(())
    }

    /// 结束cgroup资源限制
    pub fn stop(&self) -> Result<(), Error> {
        let (stopped, timer) = &*self.running;
        {
            let mut stopped = stopped.lock().unwrap();
            if !*stopped {
                return Ok(());
            }
            *stopped = false;
        }
        timer.notify_one();

        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
        if let Err(e) = self.cgroup.delete() {
            return Err(Error::DeleteCgroupsFailed(e.to_string()));
        }
        info!("cgroups controller stopped");
        Ok(())
    }
}

pub fn is_kernel_available_for_cgroups() -> bool {
    const MIN_KERNEL_VERSION_SUPPORT_CGROUP: &str = "2.6.24"; // Support cgroups from Linux 2.6.24
    let sys_uname = uname(); // kernel_version is in the format of 5.4.0-13
    sys_uname
        .release()
        .trim()
        .split_once('-')
        .unwrap_or_default()
        .0
        .ge(MIN_KERNEL_VERSION_SUPPORT_CGROUP)
}
pub fn is_cgroup_procs_writable() -> bool {
    // The cgroup.procs file can only be written after Linux 3.0. Refer to:
    // https://github.com/torvalds/linux/commit/74a1166dfe1135dcc168d35fa5261aa7e087011b
    const MIN_KERNEL_VERSION_CGROUP_PROCS: &str = "3";
    let sys_uname = uname(); // kernel_version is in the format of 5.4.0-13
    sys_uname
        .release()
        .trim()
        .split_once('-')
        .unwrap_or_default()
        .0
        .ge(MIN_KERNEL_VERSION_CGROUP_PROCS)
}

pub fn get_cgroup_cpuset(dir_path: &str) -> Result<[String; 2], io::Error> {
    let cpuset_cpus = match fs::read_to_string(format!("{}/cpuset.cpus", dir_path)) {
        Ok(file_contents) => file_contents.trim().to_string(),
        Err(e) => return Err(e),
    };
    let cpuset_mems = match fs::read_to_string(format!("{}/cpuset.mems", dir_path)) {
        Ok(file_contents) => file_contents.trim().to_string(),
        Err(e) => return Err(e),
    };
    Ok([cpuset_cpus, cpuset_mems])
}
// TODO: 判断文件存在，读取文件内容，判断字符串存在，如果不存在调用 numactl 获取信息写入文件（文件地址？）&& 执行命令，如果存在则跳过
pub fn register_resource() {}

pub fn gen_resource_info(numa_nodes: u32, cpuset: &str) -> Result<String, Error> {
    Ok(String::from("hhhh"))
}

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
