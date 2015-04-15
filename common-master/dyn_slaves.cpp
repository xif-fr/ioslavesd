#include "master.hpp"

	// Misc
#include <math.h>

	// Conf files
#include <libconfig.h++>
#include <sys/dir.h>

	// Slave connections : Network and threads
#include <socket++/handler/socket_client.hpp>
#include <socket++/base_inet.hpp>
#include <socket++/quickdefs.h>
#include <pthread.h>

std::vector<iosl_dyn_slaves::slave_info> iosl_dyn_slaves::select_slaves (const char* needed_service, ram_megs_t needed_ram, proc_power_t needed_power, bool comfortably, efficiency_ratio_t eff, bool quickly, std::function<points_t(const iosl_dyn_slaves::slave_info&)> additional_filter) {
	
		/// List slaves and open info files
	std::vector<std::pair<iosl_dyn_slaves::slave_info,libconfig::Config*>> slaves_list_cfg;
	RAII_AT_END({
		for (std::pair<iosl_dyn_slaves::slave_info,libconfig::Config*>& p : slaves_list_cfg) 
			delete p.second;
	});
	
	size_t ni;
	DIR* slaves_dir = ::opendir(IOSLAVES_MASTER_SLAVES_DIR);
	if (slaves_dir == NULL) 
		throw xif::sys_error("dyn_slaves : can't open slaves dir");
	dirent* dp = NULL;
	while ((dp = ::readdir(slaves_dir)) != NULL) {
		for (ni = 1; ni <= 5; ni++)
			if (dp->d_name[::strlen(dp->d_name)-ni] != ".conf"[5-ni]) 
				goto __dp_loop_next;
		{
			std::string fname = _S( IOSLAVES_MASTER_SLAVES_DIR,"/",std::string(dp->d_name) );
			iosl_dyn_slaves::slave_info info;
			info.sl_name = std::string(dp->d_name).substr(0, ::strlen(dp->d_name)-ni+1);
			if (info.sl_name.length() < 3 or !ioslaves::validateSlaveName(info.sl_name)) continue;
			FILE* ser_f = ::fopen(fname.c_str(), "r");
			if (ser_f == NULL)
				throw xif::sys_error(_s("failed to open slave info file for ",info.sl_name));
			libconfig::Config* conf = new libconfig::Config;
			try {
				conf->read(ser_f);
			} catch (libconfig::ConfigException& e) {
				throw xif::sys_error(_s("error in slave info file for ",info.sl_name), e.what());
			}
			slaves_list_cfg.push_back( std::pair<slave_info,libconfig::Config*>( info, conf ) );
			::fclose(ser_f);
		}
	__dp_loop_next:
		continue;
	}
	::closedir(slaves_dir);
	
		/// Pre-fill the info strcut
	std::vector<iosl_dyn_slaves::slave_info> slaves_list;
	for (const std::pair<iosl_dyn_slaves::slave_info,libconfig::Config*>& p : slaves_list_cfg) {
		iosl_dyn_slaves::slave_info info = p.first;
		libconfig::Config& cfg = *p.second;
		try {
			libconfig::Setting& caracts_grp = cfg.lookup("caracts");
			info._sl_categs_infos = std::make_tuple(0,INT32_MIN,0.f,INT32_MIN,INT32_MIN,INT32_MIN,INT32_MIN);
			info.sl_total_points = INT32_MIN;
			info.sl_start_delay = (int)cfg.lookup("start_delay");
			info.sl_power_use_full = (int)caracts_grp["power_use"];
			info.sl_usable_mem = (int)caracts_grp["tot_mem"];
			info.sl_usable_proc = (float)caracts_grp["proc_power_APPeq"];
			libconfig::Setting& other_indices_group = caracts_grp["other_indices"];
			for (int i = 0; i < other_indices_group.getLength(); i++) {
				const char* name = other_indices_group[i].getName();
				if (name == NULL) throw libconfig::ConfigException();
				float value = (float)(other_indices_group[i]);
				info.sl_fixed_indices.insert(std::pair<std::string,float>( name, value ));
			}
		} catch (libconfig::ConfigException& ce) {
			throw xif::sys_error(_s("missing/bad fields in slave info file for ",info.sl_name), ce.what());
		}
		slaves_list.push_back(info);
	}
	
		/// Contact slaves in threads
	struct _slave_contact {
			// One thread for contacting each slave
		static void* contact_thread (void* data) {
			iosl_dyn_slaves::slave_info& info = *((iosl_dyn_slaves::slave_info*)data);
			xif::polyvar stat;
			try {
				socketxx::simple_socket_client<socketxx::base_netsock> sock = iosl_master::slave_connect(info.sl_name, 0, timeval{1,0});
				sock.o_bool(true);
				sock.o_str(""); // No auth, no identification
				sock.o_bool(false);
				sock.o_char((char)ioslaves::op_code::GET_STATUS);
				stat = sock.i_var(); // Get system infos
				sock.i_char();
			} 
			catch (socketxx::dns_resolve_error&) { info.sl_status = -1; return NULL; }
			catch (socketxx::end::client_connect_error& e) { info.sl_status = -1; return NULL; }
			catch (socketxx::classic_error& e) { info.sl_status = e.get_errno(); return NULL; }
			catch (iosl_master::ldns_error&) { info.sl_status = -1; return NULL; }
			catch (...) { info.sl_status = -3; return NULL; }
			try { // Fill the info struct with fresh infos from slave
				for (const std::pair<std::string,xif::polyvar>& p : stat["services"].m()) {
					info.sl_services_status[p.first] = p.second["running"];
				}
				stat = stat["system"];
				info.sl_usable_proc = info.sl_usable_proc * (1.f - ((float)stat["proc_%"])/100.f);
				info.sl_usable_mem = (ram_megs_t)stat["mem_usable"];
			} catch (...) {
				info.sl_status = -2;
				return NULL;
			}
			info.sl_status = 0;
			return NULL;
		};
	};
	pthread_t thread_ids[slaves_list.size()];
	for (size_t i = 0; i < slaves_list.size(); i++) {
		iosl_dyn_slaves::slave_info& info = slaves_list[i];
		::pthread_create(&thread_ids[i], NULL, &_slave_contact::contact_thread, &info);
		::usleep(40000);
	}
	// Wait for all threads (1 sec timout)
	for (size_t i = 0; i < slaves_list.size(); i++) {
		pthread_join(thread_ids[i], NULL);
	}
	
		/// Apply criteria : select good slaves and sort ascendingly using points
	for (size_t i = 0; i < slaves_list.size(); i++) {
		iosl_dyn_slaves::slave_info& info = slaves_list[i];
		points_t pt = 0;
		
			// Check status
		if (info.sl_status != 0 and info.sl_status != -1)
			continue;
		
			// Service installed ?
		if (needed_service != NULL and info.sl_status == 0 and info.sl_services_status.find(needed_service) == info.sl_services_status.end()) {
			info.sl_status = -5;
			continue;
		}
		
		{ // Memory
			int16_t diff = info.sl_usable_mem - needed_ram;
			std::get<0>(info._sl_categs_infos) = diff;
			if (comfortably and info.sl_usable_mem < needed_ram) goto bye;
			#define RAM_MaxPTs 150
			#define RAM_AntiexpPw 1.004f
			#define RAM_LinF 0.016f
			points_t ram_pt = -pow(RAM_AntiexpPw, -diff + log(RAM_MaxPTs)/log(RAM_AntiexpPw)) + RAM_MaxPTs + RAM_LinF*diff;
			std::get<1>(info._sl_categs_infos) = ram_pt;
			pt += ram_pt;
		}
		{ // Proc power
			float ratio = info.sl_usable_proc / needed_power;
			std::get<2>(info._sl_categs_infos) = ratio;
			if (comfortably and info.sl_usable_proc < needed_power) goto bye;
			#define PROC_LowestRatio 0.2f
			if (ratio < PROC_LowestRatio) goto bye;
			#define PROC_InvF 170.0f
			#define PROC_LinF 15.0f
			#define PROC_StepPTs 133
			#define PROC_StepPw 250.0f
			points_t proc_pt = PROC_InvF*(-1/ratio + 1) + PROC_LinF*(ratio-1) + (2*PROC_StepPTs*( pow(PROC_StepPw, ratio)/(PROC_StepPw+pow(PROC_StepPw, ratio)) ) - PROC_StepPTs);
			std::get<3>(info._sl_categs_infos) = proc_pt;
			pt += proc_pt;
		}
		{ // Watt efficiency
			points_t penaltyPerWatt[4] = {
				[efficiency_ratio_t::REGARDLESS] = 0,
				[efficiency_ratio_t::FOR_HOURS_MEDIUM] = 3,
				[efficiency_ratio_t::FOR_DAY_HIGH] = 7,
				[efficiency_ratio_t::FOR_DAYS_HIGHEST] = 12
			};
			points_t watt_pt = info.sl_power_use_full * penaltyPerWatt[eff];
			std::get<4>(info._sl_categs_infos) = -watt_pt;
			pt -= watt_pt;
		}
		{ // Wait/Startup
			if (info.sl_status == -1) {
				if (info.sl_start_delay == 0) goto bye;
				points_t wait_pt = info.sl_start_delay * (quickly ? 8 : 3);
				std::get<5>(info._sl_categs_infos) = -wait_pt;
				pt -= wait_pt;
			} else
				std::get<5>(info._sl_categs_infos) = 0;
		}
		{ // Additional filter
			if (additional_filter)
				try {
					points_t ext_pt = additional_filter(info);
					std::get<6>(info._sl_categs_infos) = ext_pt;
					if (ext_pt == INT32_MIN) goto bye;
					pt += ext_pt;
				}
				catch (xif::polyvar::bad_type) { goto bye; }
				catch (std::runtime_error) { goto bye; }
			else
				std::get<6>(info._sl_categs_infos) = 0;
		}
		info.sl_total_points = pt;
		continue;
	bye:
		info.sl_total_points = INT32_MIN;
	}
		// Sorting
	std::sort(slaves_list.begin(), slaves_list.end());
	
	return slaves_list;
}

time_t iosl_master::slave_start (std::string slave_id, std::ostream& _log_) {
	iosl_master::on_type $poweron_type = iosl_master::on_type::_AUTO;
	socketxx::base_netsock::addr_info $on_addr = {in_addr{0},0};
	time_t $start_delay = 0;
	std::string $on_mac;
	std::string $on_gateway;
	uint16_t $on_psu_id = -1;
	std::string fname = _S( IOSLAVES_MASTER_SLAVES_DIR,"/",slave_id,".conf" );
	if (::access(fname.c_str(), F_OK) == -1) 
		throw xif::sys_error(_S("conf file not found for slave",slave_id));
	try {
		libconfig::Config conf;
		conf.readFile(fname.c_str());
		$start_delay = (int)conf.lookup("start_delay");
		if ($start_delay == 0)
			throw std::runtime_error(_S("slave ",slave_id," must be started manually"));
		libconfig::Setting& poweron_grp = conf.lookup("poweron");
		std::string type = poweron_grp["type"].operator std::string();
		if (type == "wol") {
			$poweron_type = iosl_master::on_type::WoL;
			$on_mac = poweron_grp["mac"].operator std::string();
		} else if (type == "wow") {
			$poweron_type = iosl_master::on_type::WoW;
			$on_mac = poweron_grp["mac"].operator std::string();
			$on_addr = socketxx::base_netsock::addr_info( 9, poweron_grp["disthost"].operator std::string() );
		} else if (type == "psu") {
			$poweron_type = iosl_master::on_type::PSU;
			$on_psu_id = (int)poweron_grp["psuid"];
		} else if (type == "gateway") {
			$poweron_type = iosl_master::on_type::GATEWAY;
			$on_gateway = poweron_grp["gateway"].operator std::string();
		} else
			throw std::runtime_error("invalid poweron type");
	} catch (std::exception& e) {
		throw std::runtime_error(_S("conf error in file for slave ",slave_id," : ",e.what()));
	}
	_log_ << "Waking up slave " << slave_id;
	if ($poweron_type == iosl_master::on_type::WoW) {
		_log_ << " using a magic packet for " << $on_mac << " to " << $on_addr.get_ip_str() << ":" << $on_addr.get_port() << std::endl;
		ioslaves::wol::magic_send($on_mac.c_str(), true, $on_addr.get_ip_addr().s_addr, $on_addr.get_port());
	} else if ($poweron_type == iosl_master::on_type::WoL) {
		_log_ << " using a magic packet for " << $on_mac << " in local" << std::endl;
		ioslaves::wol::magic_send($on_mac.c_str(), false);
	} else if ($poweron_type == iosl_master::on_type::GATEWAY) {
		_log_ << " via gateway '" << $on_gateway << "'" << std::endl;
		#warning TO DO : wol gateway connection
	} else if ($poweron_type == iosl_master::on_type::PSU) {
		_log_ << " via psu id " << $on_psu_id << std::endl;
		#warning TO DO : serial psu module
	}
	return $start_delay;
}
