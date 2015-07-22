/**********************************************************\
 *               -== Xif Network project ==-
 *                   ioslaves - slave side
 *
 *                       Slave status
 * *********************************************************
 * Copyright © Félix Faisant 2013-2014. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// General
#include "main.h"
using namespace xlog;
#include <xifutils/cxx.hpp>
#include <sys/dir.h>

	// Topp linux system monitor library
#ifndef IOSLAVESD_NO_TOPP
	#include <toppapi.hpp>
	#include <fstream>
	namespace ioslaves {
		std::tuple<time_t,time_t,time_t> statusLinuxCalculateUptimes ();
	}
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
	{"cpu#", 0},
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
	
	/// Linux status, using ToppAPI
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
		system_stat["cpu#"] = cpu.c_tot_cores;
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
			system_stat["memAc"] = mem.m_activeCache/MiB;
			system_stat["memAa"] = mem.m_activeAnon/MiB;
		system_stat["memI"] = (mem.m_inactiveCache + mem.m_inactiveAnon)/MiB;
			system_stat["memIc"] = mem.m_inactiveCache/MiB;
			system_stat["memIa"] = mem.m_inactiveAnon/MiB;
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
	{	// Total uptimes
		std::tuple<time_t,time_t,time_t> uptimes = ioslaves::statusLinuxCalculateUptimes();
		system_stat["totuptime"] = std::get<0>(uptimes);
		system_stat["totcputime"] = std::get<2>(uptimes);
		system_stat["uptime"] = topp::GetUptime();
	}
#else
	
	/// Mac OSX status
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
	if (r == -1) 
		throw xif::sys_error("sysctl(swap)");
	
	system_stat["mem_swap"] = swap_usage.xsu_used/MiB;
	system_stat["mem_usable"] = ((memstat.wire_count + memstat.active_count) * vm_page_size - swap_usage.xsu_used)/MiB;

	struct timeval boottime;
	size_t len = sizeof(boottime);
	
	int mib[2] = { CTL_KERN, KERN_BOOTTIME };
	r = ::sysctl(mib, 2, &boottime, &len, NULL, 0);
	if (r == -1) 
		throw xif::sys_error("sysctl(boottime)");
	
	system_stat["uptime"] = ::time(NULL) - boottime.tv_sec;
	
	#endif
	
#endif
}

void ioslaves::statusEnd () {
	time_t iosl_uptime = ::time(NULL) - start_time;
	__log__(log_lvl::LOG, NULL, logstream << "ioslavesd was running for " << iosl_uptime/60 << " minutes");
	#ifndef IOSLAVESD_NO_TOPP
	std::tuple<time_t,time_t,time_t> uptimes = ioslaves::statusLinuxCalculateUptimes();
	asroot_block();
	std::ofstream totuptime_F (IOSLAVESD_UPTIME_FILE, std::fstream::out|std::fstream::trunc);
	totuptime_F << std::get<0>(uptimes) << ' ' << std::get<1>(uptimes) << ' ' << std::get<2>(uptimes);
	#endif
}

#ifndef IOSLAVESD_NO_TOPP
std::tuple<time_t,time_t,time_t> ioslaves::statusLinuxCalculateUptimes () { 
	time_t iosl_uptime = ::time(NULL) - start_time;
	topparsing::FieldsFile F_uptime("/proc/uptime", ' ', 2);
	time_t uptime = (time_t)::atof(F_uptime.stri(0).c_str());
	time_t idletime = (time_t)( ::atof(F_uptime.stri(1).c_str()) / system_stat["cpu#"].i() );
	time_t usedtime = uptime - idletime;
	try {
		topparsing::FieldsFile F_totuptime(IOSLAVESD_UPTIME_FILE, ' ', 3);
		float factor = (float)iosl_uptime/(float)uptime;
		uptime = F_totuptime.numi(0) + iosl_uptime;
		idletime = F_totuptime.numi(1) + (time_t)((float)idletime*factor);
		usedtime = F_totuptime.numi(2) + (time_t)((float)usedtime*factor);
	} catch (...) {}
	return std::make_tuple(uptime, idletime, usedtime);
}
#endif

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
	
	info["shtdwntm"] = ::shutdown_time == 0 ? xif::polyvar() : xif::polyvar(::shutdown_time);
	
	info["keys"] = xif::polyvar::vec();
	DIR* dir = ::opendir(IOSLAVESD_KEYS_DIR);
	if (dir != NULL) {
		dirent* dp, *dentr = (dirent*) ::malloc((size_t)offsetof(struct dirent, d_name) + std::max(sizeof(dirent::d_name), (size_t)::fpathconf(dirfd(dir),_PC_NAME_MAX)) +1);
		RAII_AT_END({ ::closedir(dir); ::free(dentr); });
		int rr;
		while ((rr = ::readdir_r(dir, dentr, &dp)) != -1 and dp != NULL) {
			std::string fnam = dp->d_name;
			if (fnam.length() > 4 and fnam.substr(fnam.length()-4) == ".key") {
				std::string master = fnam.substr(0, fnam.length()-4);
				if (ioslaves::validateMasterID(master)) 
					info["keys"].v().push_back(master);
			}
		}
		if (rr == -1)
			throw xif::sys_error("slaves dir : readdir_r");
	}
	
	return info;
}
