/**********************************************************\
 *                ioslaves : ioslaves-master
 *            Common header for master programs
 *     Connection/Authentication/DynSlaves interfaces
 * *********************************************************
 * Copyright © Félix Faisant 2014-2016. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

#include "master.hpp"
using namespace xlog;
using ioslaves::answer_code;

	// Misc
#include <math.h>
#include <algorithm>

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

#define DYNSL_GATHER_INFO_CONN_TIMEOUT timeval{1,0}
#define DYNSL_GATHER_INFO_STATWAIT_TIMEOUT timeval{4,0}

std::vector<iosl_dyn_slaves::slave_info> iosl_dyn_slaves::gather_infos (std::vector<std::string> needed_tags) {
	
		/// List slaves and open info files
	std::vector<std::pair<iosl_dyn_slaves::slave_info,libconfig::Config*>> slaves_list_cfg;
	RAII_AT_END({
		for (std::pair<iosl_dyn_slaves::slave_info,libconfig::Config*>& p : slaves_list_cfg) 
			delete p.second;
	});
	
	{	size_t ni;
		DIR* slaves_dir = ::opendir(IOSLAVES_MASTER_SLAVES_DIR);
		if (slaves_dir == NULL) 
			throw xif::sys_error("dyn_slaves : can't open slaves dir");
		RAII_AT_END_L( ::closedir(slaves_dir) );
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
					throw xif::sys_error(_S("failed to open slave info file for ",info.sl_name));
				libconfig::Config* conf = new libconfig::Config;
				try {
					conf->read(ser_f);
				} catch (const libconfig::ParseException& e) {
					throw ioslaves::req_err(answer_code::INVALID_DATA, logstream << "Parse error in slave file of " << info.sl_name << " at line " << e.getLine() << " : " << e.getError());
				}
				slaves_list_cfg.push_back( std::pair<slave_info,libconfig::Config*>( info, conf ) );
				::fclose(ser_f);
			}
		__dp_loop_next:
			continue;
		}
	}
	
		/// Pre-fill the info strcut
	std::vector<iosl_dyn_slaves::slave_info> slaves_list;
	for (const std::pair<iosl_dyn_slaves::slave_info,libconfig::Config*>& p : slaves_list_cfg) {
		iosl_dyn_slaves::slave_info info = p.first;
		info.sl_status = -1;
		libconfig::Config& cfg = *p.second;
		try {
			libconfig::Setting& caracts_grp = cfg.lookup("caracts");
			caracts_grp.assertType(libconfig::Setting::TypeGroup);
			info._sl_categs_infos = std::make_tuple(0,INT32_MIN,0.f,INT32_MIN,0,INT32_MIN,INT32_MIN,INT32_MIN);
			info.sl_total_points = (points_t)INT32_MIN;
			info.sl_start_delay = (uint16_t)(int)cfg.lookup("start_delay");
			info.sl_power_use_idle = (power_watt_t)(int)caracts_grp["pelec_idle"];
			info.sl_power_use_full = (power_watt_t)(int)caracts_grp["pelec_full"];
			info.sl_usable_mem = (ram_megs_t)(int)caracts_grp["tot_mem"];
			info.sl_proc_threads = (uint8_t)(int)caracts_grp["proc_threads"];
			info.sl_usable_proc = (float)caracts_grp["proc_power"];
			libconfig::Setting& other_indices_group = caracts_grp["other_indices"];
			other_indices_group.assertType(libconfig::Setting::TypeGroup);
			for (int i = 0; i < other_indices_group.getLength(); i++) {
				std::string name = other_indices_group[i].getName();
				float value = (float)(other_indices_group[i]);
				info.sl_fixed_indices.insert({ name, value });
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
		} catch (const libconfig::SettingException& e) {
			throw ioslaves::req_err(answer_code::INVALID_DATA, logstream << "Missing/bad field @" << e.getPath() << " in slave file of " << info.sl_name);
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
				socketxx::io::simple_socket<socketxx::base_netsock> sock = iosl_master::slave_connect(info.sl_name, 0, DYNSL_GATHER_INFO_CONN_TIMEOUT);
				sock.o_bool(true);
				sock.o_str(""); // No auth, no identification
				sock.o_bool(false);
				sock.o_char((char)ioslaves::op_code::GET_STATUS);
				sock.set_read_timeout(DYNSL_GATHER_INFO_STATWAIT_TIMEOUT);
				stat = sock.i_var(); // Get system infos
				sock.i_char();
			} 
			catch (const socketxx::dns_resolve_error&) { info.sl_status = -1; return NULL; }
			catch (const socketxx::end::client_connect_error& e) { info.sl_status = -1; return NULL; }
			catch (const socketxx::classic_error& e) { info.sl_status = e.std_errno; return NULL; }
			catch (const iosl_master::ldns_error&) { info.sl_status = -1; return NULL; }
			catch (...) { info.sl_status = -3; return NULL; }
			try { // Fill the info struct with fresh infos from slave
				info._sl_raw_infos = stat;
				for (const std::pair<std::string,xif::polyvar>& p : stat["services"].m()) {
					info.sl_services_status[p.first] = p.second["running"];
				}
				stat = stat["system"];
				info.sl_usable_proc = info.sl_usable_proc * (1.f - ((float)stat["proc_%"])/100.f);
				info.sl_usable_mem = (ram_megs_t)std::max<int>(0, stat["mem_usable"]);
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
		thread_ids[i] = (pthread_t)NULL;
		iosl_dyn_slaves::slave_info& info = slaves_list[i];
		if (info.sl_status != -1) continue;
		::pthread_create(&thread_ids[i], NULL, &_slave_contact::contact_thread, &info);
		::usleep(40000);
	}
	// Wait for all threads (1 sec timout)
	for (size_t i = 0; i < slaves_list.size(); i++) {
		if (thread_ids[i] != (pthread_t)NULL)
			::pthread_join(thread_ids[i], NULL);
	}
	
	return slaves_list;
}

	/// Apply criteria : select good slaves and sort ascendingly using points
void iosl_dyn_slaves::select_slaves (std::vector<slave_info>& slaves_list,
                                     const char* needed_service, 
                                     ram_megs_t needed_ram, proc_power_t needed_power,
                                     efficiency_ratio_t eff, proc_power_t mean_power, float usable_threads,
                                     bool quickly, 
                                     std::function<points_t(const iosl_dyn_slaves::slave_info&)> additional_filter) {
	
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
			#define RAM_MaxPTs 150
			#define RAM_AntiexpPw 1.004f
			#define RAM_LinF 0.016f
			points_t ram_pt = ::lroundf( -powf(RAM_AntiexpPw, -diff + logf(RAM_MaxPTs)/logf(RAM_AntiexpPw)) + RAM_MaxPTs + RAM_LinF*diff );
			std::get<1>(info._sl_categs_infos) = ram_pt;
			pt += ram_pt;
		}
		{ // Proc power
			float tot_usable_proc = std::min((float)info.sl_proc_threads, std::max(1.0f,usable_threads)) * info.sl_usable_proc;
			float ratio = tot_usable_proc / needed_power;
			std::get<2>(info._sl_categs_infos) = ratio;
			#define PROC_LowestRatio 0.2f
			if (ratio < PROC_LowestRatio) goto bye;
			#define PROC_InvF 170.0f
			#define PROC_LinF 15.0f
			#define PROC_StepPTs 133
			#define PROC_StepPw 250.0f
			points_t proc_pt = ::lroundf( PROC_InvF*(-1/ratio + 1) + PROC_LinF*(ratio-1) + (2*PROC_StepPTs*( powf(PROC_StepPw, ratio)/(PROC_StepPw+powf(PROC_StepPw, ratio)) ) - PROC_StepPTs) );
			std::get<3>(info._sl_categs_infos) = proc_pt;
			pt += proc_pt;
		}
		{ // Watt efficiency
			points_t penaltyPerWatt[4] = {
				[efficiency_ratio_t::REGARDLESS] = 0,
				[efficiency_ratio_t::FOR_HOURS_MEDIUM] = 1,
				[efficiency_ratio_t::FOR_DAY_HIGH] = 2,
				[efficiency_ratio_t::FOR_DAYS_HIGHEST] = 4
			};
			float mqproc = std::min(mean_power/info.sl_usable_proc, 1.f);
			if (info.sl_status == 0) info.sl_power_use_idle = 0;
			power_watt_t estimated_power = (power_watt_t)::lroundf(  mqproc*info.sl_power_use_full + (1.f-mqproc)*info.sl_power_use_idle );
			std::get<4>(info._sl_categs_infos) = estimated_power;
			points_t watt_pt = estimated_power * penaltyPerWatt[eff];
			std::get<5>(info._sl_categs_infos) = -watt_pt;
			pt -= watt_pt;
		}
		{ // Wait/Startup
			if (info.sl_status == -1) {
				if (info.sl_start_delay == 0) goto bye;
				points_t wait_pt = info.sl_start_delay * (quickly ? 8 : 3);
				std::get<6>(info._sl_categs_infos) = -wait_pt;
				pt -= wait_pt;
			} else
				std::get<6>(info._sl_categs_infos) = 0;
		}
		{ // Additional filter
			if (additional_filter)
				try {
					points_t ext_pt = additional_filter(info);
					std::get<7>(info._sl_categs_infos) = ext_pt;
					if (ext_pt == INT32_MIN) goto bye;
					pt += ext_pt;
				}
				catch (const xif::polyvar::bad_type) { goto bye; }
				catch (const std::runtime_error) { goto bye; }
			else
				std::get<7>(info._sl_categs_infos) = 0;
		}
		info.sl_total_points = pt;
		continue;
	bye:
		info.sl_total_points = INT32_MIN;
	}
		// Sorting
	std::sort(slaves_list.begin(), slaves_list.end());
}

time_t iosl_master::slave_start (std::string slave_id, std::string master_id) {
	logl_t l;
	iosl_master::on_type $poweron_type = iosl_master::on_type::_AUTO;
	socketxx::base_netsock::addr_info $on_addr = {in_addr{0},0};
	time_t $start_delay = 0;
	std::string $on_mac;
	std::string $on_gateway;
	std::string fname = _S( IOSLAVES_MASTER_SLAVES_DIR,"/",slave_id,".conf" );
	if (::access(fname.c_str(), F_OK) == -1) 
		throw ioslaves::req_err(answer_code::NOT_FOUND, logstream << "Slave settings file not found for '" << slave_id << "'");
	try {
		libconfig::Config conf;
		conf.readFile(fname.c_str());
		$start_delay = (int)conf.lookup("start_delay");
		if ($start_delay == 0)
			throw ioslaves::req_err(answer_code::BAD_TYPE, logstream << "Slave '" << slave_id << "' must be started manually");
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
		} else if (type == "gateway") {
			$poweron_type = iosl_master::on_type::GATEWAY;
			$on_gateway = poweron_grp["gateway"].operator std::string();
			if (!ioslaves::validateSlaveName($on_gateway)) 
				throw std::runtime_error("Invalid slave name as wake gateway");
		} else 
			throw std::runtime_error("Invalid poweron type");
	} catch (const libconfig::SettingException& e) {
		throw ioslaves::req_err(answer_code::INVALID_DATA, logstream << "Missing/bad setting @" << e.getPath() << " in slave file of '" << slave_id << "'");
	} catch (const std::exception& e) {
		throw ioslaves::req_err(answer_code::INVALID_DATA, logstream << "Error in slave file of '" << slave_id << "' : " << e.what());
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
		try {
			socketxx::io::simple_socket<socketxx::base_netsock> sock = iosl_master::slave_api_service_connect($on_gateway, master_id, "wake-gateway");
			sock.o_str(slave_id);
			ioslaves::answer_code o = (ioslaves::answer_code)sock.i_char();
			if (o != ioslaves::answer_code::OK) 
				throw ioslaves::req_err(o, logstream << "Wake-gateway service failed to start slave (" << ioslaves::getAnswerCodeDescription(o) << ")");
			time_t dist_delay = sock.i_int<uint16_t>();
			if (dist_delay > $start_delay)
				$start_delay = dist_delay;
		} catch (const socketxx::classic_error& e) {
			throw ioslaves::req_err(answer_code::ERROR, logstream << "Network error with wake-gateway service : " << e.what());
		} catch (const master_err& e) {
			throw ioslaves::req_err(answer_code::ERROR, logstream << "Master error while connecting to wake-gateway service : " << e.what());
		}
		__log__(log_lvl::DONE, "WAKE", "Start request relayed !");
	}
	return $start_delay;
}
