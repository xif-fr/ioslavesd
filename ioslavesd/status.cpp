/**********************************************************\
 *               -== Xif Network project ==-
 *                   ioslaves - slave side
 *
 *                       Slave status
 * *********************************************************
 * Copyright © Félix Faisant 2013-2014. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

#include "main.h"

	// Topp linux system monitor library
#ifndef IOSLAVESD_NO_TOPP
	#include <toppapi.hpp>
#else
	// Mach headers & cie.
	#ifdef __MACH__
		#include <limits.h>
		#include <mach/mach.h>
		#include <mach/mach_error.h>
		#include <sys/sysctl.h>
	#endif
#endif
#define MiB (1024*1024)

xif::polyvar::map ioslaves::system_stat ({
	{"proc_%", 0.0f},
	{"mem_tot", 0},
	{"mem_free", 0},
	{"mem_usable", 0},
	{"mem_used", 0},
	{"mem_swap", 0},
	{"memK", 0},
	{"memI", 0},
	{"memA", 0},
	{"net_up", 0},
	{"net_down", 0},
	{"process_num", 0},
});

void ioslaves::statusFrame () {
#ifndef IOSLAVESD_NO_TOPP
		// Time
	timeval now;
	::gettimeofday(&now, NULL);
	static timeval lastT = {0,0};
	lastT = topp::setDeltaT(lastT);
	{ // CPU
		topparsing::PropertiesFile F_cpuinfo("/proc/cpuinfo");
		topp::cpu cpu = topp::GetCpuInfo(F_cpuinfo);
		topparsing::PropertiesFile F_procstat ("/proc/stat");
		topp::cputimes cputimes = topp::GetCpuUsage(cpu.c_tot_cores, F_procstat);
		float cpu_percent = (cputimes.tot_sys+cputimes.tot_usr)/(float)cputimes.tot_tot *100.f;
		system_stat["proc_%"] = cpu_percent;
	}
	{ // RAM
		topparsing::PropertiesFile F_meminfo ("/proc/meminfo");
		topp::mem mem = topp::GetMemInfo(F_meminfo);
		system_stat["mem_tot"] = mem.m_total/MiB;
		system_stat["mem_free"] = mem.m_free/MiB;
		system_stat["mem_swap"] = mem.m_swapUsed/MiB;
		system_stat["mem_used"] = (mem.m_total - mem.m_free)/MiB;
		system_stat["mem_usable"] = (mem.m_usable-mem.m_swapUsed)/MiB;
		system_stat["memK"] = (mem.m_kernel + mem.m_buffers)/MiB;
		system_stat["memA"] = (mem.m_activeCache + mem.m_activeAnon)/MiB;
		system_stat["memI"] = (mem.m_inactiveCache + mem.m_inactiveAnon)/MiB;
	}
	{ // Net
		topparsing::TableFile F_netdev = topp::Parse_F_netdev();
		topp::throughput net = topp::GetNetTotThroughputs(F_netdev);
		system_stat["net_up"] = net.up_inst;
		system_stat["net_down"] = net.down_inst;
	}
	{ // Process
		std::vector<pid_t> pids = topp::GetPIDs();
		system_stat["process_num"] = pids.size();
	}
#else
	
	#ifdef __MACH__

	kern_return_t kr;
	int r;
	
		// CPU stats
	
	natural_t cpus;
	processor_info_array_t info_array;
	mach_msg_type_number_t info_count;
	
	kr = ::host_processor_info(::mach_host_self(), 
										PROCESSOR_CPU_LOAD_INFO, &cpus, &info_array, &info_count);
	if (kr != KERN_SUCCESS) {
		::mach_error("host_processor_info error : ", kr);
		return;
	}
	
	processor_cpu_load_info_data_t* cpu_load_info = (processor_cpu_load_info_data_t*)info_array;
	static processor_cpu_load_info_data_t* cpu_load_last = NULL;
	if (cpu_load_last == NULL) cpu_load_last = new processor_cpu_load_info_data_t[cpus];
	
	unsigned int ticks_usr = 0, ticks_sys = 0, ticks_idle = 0, ticks_total = 0;
	
	for (natural_t i = 0; i < cpus; i++) {
		auto calc_ticks = [&] (uint8_t cpu_state) -> unsigned int {
			RAII_AT_END({ 
				cpu_load_last[i].cpu_ticks[cpu_state] = cpu_load_info[i].cpu_ticks[cpu_state];
			});
			if (cpu_load_info[i].cpu_ticks[cpu_state] >= cpu_load_last[i].cpu_ticks[cpu_state]) 
				return cpu_load_info[i].cpu_ticks[cpu_state] - cpu_load_last[i].cpu_ticks[cpu_state];
			else 
				return cpu_load_info[i].cpu_ticks[cpu_state] + (UINT_MAX - cpu_load_last[i].cpu_ticks[cpu_state] + 1);
		};
		ticks_sys += calc_ticks(CPU_STATE_SYSTEM);
		ticks_usr += calc_ticks(CPU_STATE_USER) + calc_ticks(CPU_STATE_NICE);
		ticks_idle += calc_ticks(CPU_STATE_IDLE);
	}
	ticks_total = ticks_sys + ticks_idle + ticks_usr;
	
	::vm_deallocate(mach_task_self(), (vm_address_t)info_array, info_count);
	
	float cpu_tot_load = (float)(ticks_sys+ticks_usr) / (float)ticks_total;
	system_stat["proc_%"] = cpu_tot_load * 100.f;
	
		// Memory stats
	
	struct vm_statistics64 memstat;
	::bzero(&memstat, sizeof(vm_statistics64));
	
	mach_msg_type_number_t vm_count = HOST_VM_INFO64_COUNT;
	kr = ::host_statistics64(::mach_host_self(), 
									 HOST_VM_INFO64, (host_info64_t)&memstat, &vm_count);
	if (kr != KERN_SUCCESS) {
		::mach_error("host_statistics64 error : ", kr);
		return;
	}
	
	uint64_t memtot_count = memstat.wire_count + memstat.active_count + memstat.inactive_count + memstat.free_count;
	system_stat["mem_tot"] = (memtot_count * vm_page_size)/MiB;
	system_stat["mem_free"] = (memstat.free_count * vm_page_size)/MiB;
	system_stat["mem_used"] = ((memtot_count - memstat.free_count) * vm_page_size)/MiB;
	system_stat["memK"] = (memstat.wire_count * vm_page_size)/MiB;
	system_stat["memA"] = (memstat.active_count * vm_page_size)/MiB;
	system_stat["memI"] = (memstat.inactive_count * vm_page_size)/MiB;
	
	struct xsw_usage swap_usage;
	size_t swap_usage_sz = sizeof(xsw_usage);
	::bzero(&swap_usage, sizeof(xsw_usage));
	
	int swapMIB[] = { CTL_VM, VM_SWAPUSAGE };
	r = ::sysctl(swapMIB, 2, &swap_usage, &swap_usage_sz, NULL, 0);
	
	if (r == -1) {
		::perror("sysctl(swap) error");
		return;
	}
	
	system_stat["mem_swap"] = swap_usage.xsu_used/MiB;
	system_stat["mem_usable"] = ((memstat.wire_count + memstat.active_count) * vm_page_size - swap_usage.xsu_used)/MiB;
	
	#endif
	
#endif
}

xif::polyvar ioslaves::getStatus (bool full) {
	std::map<std::string,xif::polyvar> info;
	
	info["me"] = hostname;
	
	info["port"] = ioslavesd_listening_port;
	
	info["services"] = xif::polyvar::map();
	for (const ioslaves::service* s : ioslaves::services_list) 
		info["services"][s->s_name.c_str()] = xif::polyvar::map({
			{"running", s->ss_status_running},
			{"info", (full ? ioslaves::serviceStatus(s) : xif::polyvar())}
		});
	
	info["ports"] = xif::polyvar::vec();
	for (ioslaves::upnpPort& port : ports_to_reopen) {
		info["ports"].push_back( (port.p_range_sz != 1) ? 
			xif::polyvar::map({
				{"port_beg", port.p_ext_port},
				{"port_end", port.p_ext_port+port.p_range_sz-1},
				{"proto", port.p_proto==ioslaves::upnpPort::TCP? "TCP": "UDP"},
				{"descr", port.p_descr},
			})
			: xif::polyvar::map({
				{"port", port.p_ext_port},
				{"proto", port.p_proto==ioslaves::upnpPort::TCP? "TCP": "UDP"},
				{"descr", port.p_descr},
			})
		);
	}
	
	info["system"] = ioslaves::system_stat;
	
	return info;
}
