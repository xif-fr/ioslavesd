/**********************************************************\
 *               -== Xif Network project ==-
 *                      ioslaves-master
 *            Common header for master programs
 * *********************************************************
 * Copyright © Félix Faisant 2013-2015. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common
#define XIF_LOG_DEFAULT_LOGSTREAM
#include "log.h"
#include "common.hpp"
#include <xifutils/cxx.hpp>

#ifdef IOSLAVES_MASTER_FINAL

	// Logging
#include <xifutils/optctx.hpp>
#define LOG_ARROW       (optctx::interactive ? "\033[34;1m=> \033[0m"   : "<log_arrow imp/>")
#define LOG_ARROW_OK    (optctx::interactive ? "\033[32;1m=> \033[0m"   : "<log_arrow ok/>")
#define LOG_ARROW_ERR   (optctx::interactive ? "\033[31;1m=> \033[0m"   : "<log_arrow err/>")
#define LOG_AROBASE     (optctx::interactive ? "\033[34m @ \033[0m"     : "<log_arobase imp/>")
#define LOG_AROBASE_OK  (optctx::interactive ? "\033[32m @ \033[0m"     : "<log_arobase ok/>")
#define LOG_AROBASE_ERR (optctx::interactive ? "\033[31m @ \033[0m"     : "<log_arobase err/>")
#define NICE_WARNING    (optctx::interactive ? "\033[1;31m/!\\\033[0m " : "<log_warning/>")
#define COLOR_RED       (optctx::interactive ? "\033[1;31m"             : "<log_color red>")
#define COLOR_YELLOW    (optctx::interactive ? "\033[1;33m"             : "<log_color yellow>")
#define COLOR_GREEN     (optctx::interactive ? "\033[32m"               : "<log_color green>")
#define COLOR_RESET     (optctx::interactive ? "\033[0m"                : "</log_color>")

#endif

	// Files
#ifndef IOSLAVES_MASTER_DIR
	#define IOSLAVES_MASTER_DIR "/var/ioslaves/master"
#endif
#define IOSLAVES_MASTER_KEYS_DIR _s(IOSLAVES_MASTER_DIR,"/keys")
#define IOSLAVES_MASTER_SLAVES_DIR _s(IOSLAVES_MASTER_DIR,"/slaves")
#define IOSLAVES_MASTER_KEYS_MODELS_DIR "/usr/share/ioslaves/master/key-perms/"

	// Network
#include <socket++/io/simple_socket.hpp>
#include <socket++/handler/socket_client.hpp>
#include <socket++/base_inet.hpp>
#include <socket++/quickdefs.h>
#define IOSLAVES_MASTER_DEFAULT_PORT 2929
#define HAVE_STDBOOL_H // LDNS bug
#include <ldns/ldns.h>

	// Master errors
class master_err : public std::runtime_error { 
	public: int ret; bool down;
	master_err (std::string descr, int retcode, bool down = false) : std::runtime_error(descr), ret(retcode), down(down) {} 
};
#define EXIT_FAILURE_CONN 20
#define EXIT_FAILURE_AUTH 21
#define EXIT_FAILURE_COMM 22
#define EXIT_FAILURE_IOSL 23
#define EXIT_FAILURE_ERR  24

	/// Public connect API

namespace iosl_master { 
	extern bool $leave_exceptions;
	
		// Test if a slave is up
	bool slave_test (std::string slave_id);
		// Start slave
	enum class on_type { _AUTO, WoL, WoW, GATEWAY, PSU };
	time_t slave_start (std::string slave_id, std::string master_id); // Automatically choose a start method with slave files and try to start slave

		// Connection
	class ldns_error : public std::runtime_error { public: ldns_error (ldns_status r) noexcept : std::runtime_error(_S("ldns error : ",ldns_error_str[r].name)) {} };
	in_port_t slave_get_port_dns (std::string slave_id);
	socketxx::base_netsock slave_connect (std::string slave_id, in_port_t default_port = IOSLAVES_MASTER_DEFAULT_PORT, timeval timeout = {1,0}); // Establish a raw connection to slave
	
		// Authentification
	void authenticate (socketxx::io::simple_socket<socketxx::base_netsock> slave_sock, std::string key_id); // Authenticate with key_id.key
	
		// Opperations
	void slave_command (socketxx::io::simple_socket<socketxx::base_netsock> slave_sock, std::string master_id, ioslaves::op_code opp); // Apply operation
	void slave_command_auth (socketxx::io::simple_socket<socketxx::base_netsock> slave_sock, std::string master_id, ioslaves::op_code opp, std::string key_id); // Authenticate the apply operation
	
		// All-in-one
	socketxx::base_netsock slave_api_service_connect (std::string slave_id, std::string master_id, std::string api_service, timeval timeout = {1,0}); // Connect to slave, authenticate with master_id.slave_id.key, then connect to API service
}

	/// Wake on Lan/Wan sender

namespace ioslaves { namespace wol {
	
	void magic_send (const char* mac_addr, bool wan, in_addr_t wan_ip = 0, in_port_t wan_port = 0);
		
}}

	/// Dynamic service management and slave selecting API

#include <map>
#include <vector>
#include <functional>
#include <tuple>

namespace iosl_dyn_slaves {
	
	typedef uint16_t ram_megs_t;
	typedef float proc_power_t;
	typedef uint16_t power_watt_t;
	enum efficiency_ratio_t { REGARDLESS, FOR_HOURS_MEDIUM, FOR_DAY_HIGH, FOR_DAYS_HIGHEST };
	typedef int32_t points_t; // negative for depreciate
	
	struct slave_info {
		std::string sl_name;
		int sl_status = -1; /* 0: up | -1: down | -2: bad data | -3: error | >0: errno | -4: tag unsatisfied | -5: no service */
		uint16_t sl_start_delay = 0;
		power_watt_t sl_power_use_idle = UINT16_MAX, sl_power_use_full = UINT16_MAX;
		uint8_t sl_proc_threads = 1;
		std::map<std::string,bool> sl_services_status;
		ram_megs_t sl_usable_mem = 0;
		proc_power_t sl_usable_proc = 0;
		std::map<std::string,float> sl_fixed_indices;
		points_t sl_total_points = 0;
		std::vector<std::string> sl_tags;
		std::tuple<off_t,points_t, float,points_t, power_watt_t,points_t, points_t, points_t> _sl_categs_infos;
					/*    mem            proc                elec. power       wait     custom */
		bool operator< (const slave_info& o) const { return this->sl_total_points > o.sl_total_points; }
	};
	
	std::vector<slave_info> select_slaves (const char* needed_service = NULL, 
														ram_megs_t needed_ram = 0, proc_power_t needed_power = 0,
														efficiency_ratio_t eff = REGARDLESS, proc_power_t mean_power = 0, float usable_threads = 1,
														bool quickly = true, 
														std::vector<std::string> needed_tags = {},
														std::function<points_t(const iosl_dyn_slaves::slave_info&)> additional_filter = NULL);
	
}
