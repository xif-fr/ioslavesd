#include "master.hpp"
using namespace xlog;

	// Misc
#include <math.h>

	// Conf files
#define private public
#include <libconfig.h++>
#undef private
#include <sys/dir.h>

	// Slave connections : Network and threads
#include <socket++/handler/socket_client.hpp>
#include <socket++/base_inet.hpp>
#include <socket++/quickdefs.h>
#include <pthread.h>

std::vector<iosl_dyn_slaves::slave_info> iosl_dyn_slaves::select_slaves (const char* needed_service, 
																								 ram_megs_t needed_ram, proc_power_t needed_power, 
																								 bool comfortably, 
																								 efficiency_ratio_t eff, 
																								 bool quickly, 
																								 std::vector<std::string> needed_tags,
																								 std::function<points_t(const iosl_dyn_slaves::slave_info&)> additional_filter) {
	
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
	dirent* dp, *dentr = (dirent*) ::malloc(
		(size_t)offsetof(struct dirent, d_name) + std::max(sizeof(dirent::d_name), (size_t)::fpathconf(dirfd(slaves_dir),_PC_NAME_MAX)) +1);
	RAII_AT_END_N(dir, {
		::closedir(slaves_dir);
		::free(dentr);
	});
	int rr;
	while ((rr = ::readdir_r(slaves_dir, dentr, &dp)) != -1 and dp != NULL) {
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
				throw xif::sys_error(_S("failed to open slave info file for ",info.sl_name));
			libconfig::Config* conf = new libconfig::Config;
			try {
				conf->read(ser_f);
			} catch (libconfig::ConfigException& e) {
				throw xif::sys_error(_S("error in slave info file for ",info.sl_name), e.what());
			}
			slaves_list_cfg.push_back( std::pair<slave_info,libconfig::Config*>( info, conf ) );
			::fclose(ser_f);
		}
	__dp_loop_next:
		continue;
	}
	if (rr == -1)
		throw xif::sys_error("slaves dir : readdir_r");
	
		/// Pre-fill the info strcut
	std::vector<iosl_dyn_slaves::slave_info> slaves_list;
	for (const std::pair<iosl_dyn_slaves::slave_info,libconfig::Config*>& p : slaves_list_cfg) {
		iosl_dyn_slaves::slave_info info = p.first;
		info.sl_status = -1;
		libconfig::Config& cfg = *p.second;
		try {
			libconfig::Setting& caracts_grp = cfg.lookup("caracts");
			caracts_grp.assertType(libconfig::Setting::TypeGroup);
			info._sl_categs_infos = std::make_tuple(0,INT32_MIN,0.f,INT32_MIN,INT32_MIN,INT32_MIN,INT32_MIN);
			info.sl_total_points = (points_t)INT32_MIN;
			info.sl_start_delay = (int)cfg.lookup("start_delay");
			info.sl_power_use_full = (int)caracts_grp["power_use"];
			info.sl_usable_mem = (int)caracts_grp["tot_mem"];
			info.sl_usable_proc = (float)caracts_grp["proc_power"];
			libconfig::Setting& other_indices_group = caracts_grp["other_indices"];
			other_indices_group.assertType(libconfig::Setting::TypeGroup);
			for (int i = 0; i < other_indices_group.getLength(); i++) {
				const char* name = other_indices_group[i].getName();
				if (name == NULL) throw libconfig::ConfigException();
				float value = (float)(other_indices_group[i]);
				info.sl_fixed_indices.insert(std::pair<std::string,float>( name, value ));
			}
			libconfig::Setting& tags_list = cfg.lookup("tags");
			tags_list.assertType(libconfig::Setting::TypeArray);
			for (int i = 0; i < tags_list.getLength(); i++) {
				info.sl_tags.push_back( tags_list[i].operator std::string() );
			}
				// Checking tags
			for (const std::string& needed_tag : needed_tags) {
				for (const std::string& present_tag : info.sl_tags) {
					if (needed_tag == present_tag) 
						goto _next;
				}
				info.sl_status = -4;
				break;
			_next:;
			}
		} catch (libconfig::ConfigException& ce) {
			throw xif::sys_error(_S("missing/bad fields in slave info file for ",info.sl_name), ce.what());
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
		if (info.sl_status != -1) continue;
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

time_t iosl_master::slave_start (std::string slave_id) {
	logl_t l;
	iosl_master::on_type $poweron_type = iosl_master::on_type::_AUTO;
	socketxx::base_netsock::addr_info $on_addr = {in_addr{0},0};
	time_t $start_delay = 0;
	std::string $on_mac;
	std::string $on_gateway;
	uint16_t $on_psu_id = -1;
	std::string fname = _S( IOSLAVES_MASTER_SLAVES_DIR,"/",slave_id,".conf" );
	if (::access(fname.c_str(), F_OK) == -1) 
		throw ioslaves::req_err(ioslaves::answer_code::NOT_FOUND, "WAKE", logstream << "Slave settings file not found for '" << slave_id << "'");
	try {
		libconfig::Config conf;
		conf.readFile(fname.c_str());
		$start_delay = (int)conf.lookup("start_delay");
		if ($start_delay == 0)
			throw ioslaves::req_err(ioslaves::answer_code::BAD_TYPE, "WAKE", logstream << "Slave '" << slave_id << "' must be started manually");
		libconfig::Setting& poweron_grp = conf.lookup("poweron");
		poweron_grp.assertType(libconfig::Setting::TypeGroup);
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
		throw ioslaves::req_err(ioslaves::answer_code::INVALID_DATA, "WAKE", logstream << "Setting error in conf file of '" << slave_id << "' : " << e.what());
	}
	__log__(log_lvl::LOG, "WAKE", logstream << "Waking up slave '" << slave_id << "'", LOG_WAIT, &l);
	if ($poweron_type == iosl_master::on_type::WoW) {
		__log__(log_lvl::LOG, "WAKE", logstream << "using a magic packet for " << $on_mac << " to " << $on_addr.get_ip_str() << ":" << $on_addr.get_port(), LOG_ADD, &l);
		ioslaves::wol::magic_send($on_mac.c_str(), true, $on_addr.get_ip_addr().s_addr, $on_addr.get_port());
	} 
	else if ($poweron_type == iosl_master::on_type::WoL) {
		__log__(log_lvl::LOG, "WAKE", logstream << "using a magic packet for " << $on_mac << " to local broadcast.", LOG_ADD, &l);
		ioslaves::wol::magic_send($on_mac.c_str(), false);
	} 
	else if ($poweron_type == iosl_master::on_type::GATEWAY) {
		__log__(log_lvl::LOG, "WAKE", logstream << "via gateway '" << $on_gateway << "'...", LOG_ADD, &l);
		#warning TO DO : wol gateway connection
	} 
	else if ($poweron_type == iosl_master::on_type::PSU) {
		__log__(log_lvl::LOG, "WAKE", logstream << "via serial PSU #" << $on_psu_id << "...", LOG_ADD, &l);
		#warning TO DO : serial psu module
	}
	return $start_delay;
}
