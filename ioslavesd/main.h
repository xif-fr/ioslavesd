/***********************************************************\
 *               -== Xif Network project ==-
 *                   ioslaves - slave side
 *            Control interface for XifNet services
 *
 *                 Main header for salve side
 * *********************************************************
 * Copyright © Félix Faisant 2013-2015. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

#ifndef _IOSLAVESD_MAIN_H
#define _IOSLAVESD_MAIN_H

	// Common / General
#define XIF_LOG_DEFAULT_LOGSTREAM
#include "log.h"
#include "common.hpp"
#include <list>
#include <vector>

	// Network
#include <socket++/base_inet.hpp>
#include <socket++/io/simple_socket.hpp>
#include <socket++/quickdefs.h>
#define IOSLAVESD_DNS_SLAVE_KEY_ID_DEFAULT_NAME "-dyndns-"

	/// UPnP port mapping
#include <sys/time.h>
inline uint64_t tm2us (timeval tv) { return tv.tv_sec*1000000+tv.tv_usec; }
inline uint64_t tmdiff (timeval tv1, timeval tv2) { return (tv1.tv_sec-tv2.tv_sec)*1000000 + (tv1.tv_usec-tv2.tv_usec); }
namespace ioslaves {
	class upnpError : public std::runtime_error {
	public: 
		bool fatal;
		int ret;
		upnpError (std::string descr, int r = -1, bool is_fatal = true) : std::runtime_error(descr), fatal(is_fatal), ret(r) {}
	};
	struct upnpPort { 
		in_port_t p_ext_port;
		enum proto { TCP='T', UDP='U' } p_proto;
		in_port_t p_int_port;
		uint16_t p_range_sz;
		std::string p_descr;
		timeval _lastopen; bool _is_verifiable;
	};
	void upnpInit ();
	bool upnpPortRangeCollision (in_port_t ext_port, uint16_t range_sz, ioslaves::upnpPort::proto proto);
	bool upnpPortRangeExists (ioslaves::upnpPort p);
	void upnpOpenPort (upnpPort portToOpen);
	void upnpClosePort (upnpPort portToClose);
	void upnpReopen ();
	void upnpShutdown ();
}
extern std::vector<ioslaves::upnpPort> ports_to_reopen;
extern bool enable_upnp;
extern time_t ports_reopen_interval;
extern bool ioslavesd_listening_port_open;
extern bool ports_reopen_justafter;
extern bool upnp_cache_deviceurl;
extern time_t ports_check_interval;

	// ioslaves' files
#define IOSLAVESD_SERVICE_FILE_EXT ".service"
#ifdef IOSLAVES_DIR					/* centralised ioslavesd dir */
	#define IOSLAVESD_ETC_DIR			IOSLAVES_DIR
	#define IOSLAVESD_API_DL_DIR		IOSLAVES_DIR"/services/api"
	#define IOSLAVESD_LOG_FILE			IOSLAVES_DIR"/ioslavesd.log"
	#define IOSLAVESD_RUN_FILES		IOSLAVES_DIR
	#define IOSLAVESD_DB_FILES 		IOSLAVES_DIR
#elif defined(IOSLAVES_FHS)		/* FHS standard dirs */
	#define IOSLAVESD_ETC_DIR			"/etc/ioslavesd"
	#define IOSLAVESD_API_DL_DIR		"/usr/lib/ioslavesd/api-services"
	#define IOSLAVESD_LOG_FILE			"/var/log/ioslavesd.log"
	#define IOSLAVESD_RUN_FILES		"/var/run"
	#define IOSLAVESD_DB_FILES 		"/var/db"
#endif
#define IOSLAVESD_CONF_FILE			IOSLAVESD_ETC_DIR"/ioslavesd.conf"
#define IOSLAVESD_SERVICE_FILES_DIR	IOSLAVESD_ETC_DIR"/services"
#define IOSLAVESD_KEYS_DIR				IOSLAVESD_ETC_DIR"/keys"
#define IOSLAVESD_UPTIME_FILE			IOSLAVESD_DB_FILES"/uptime.iosl"

	// ioslavesd API
#include <dlfcn.h>
typedef void* dl_t;
#define IOSLAVESD_API_MAIN_PROG
#include "api.h"

	// misc variables
extern in_port_t ioslavesd_listening_port;
extern char hostname[64];
extern bool shutdown_ignore_err;
extern time_t start_time;
extern time_t shutdown_time;
extern uid_t ioslaves_user_id;
extern gid_t ioslaves_group_id;

	// Log
#include "log.h"
struct log_entry {
	time_t le_time;
	const char* le_part;
	std::string le_msg;
	xlog::log_lvl le_lvl;
};
extern std::vector<log_entry> log_history;
extern const char* log_file_path;

	// ioslavesd
namespace ioslaves {
	
		/// Service structure
	struct service {
		std::string s_name;
		enum class type { SYSTEMCTL, PROG_DEAMON, IOSLPLUGIN } s_type;
			static type strToType (std::string str);
			std::string typeToStr ();
		std::vector<ioslaves::upnpPort> s_ports;
		std::string s_command;
		union {
			struct { } systemctl;
			struct { char* pid_file; char* execnam; } exec;
			struct { dl_t handle; } plugin;
		} spec;
		bool ss_status_running;
		bool ss_shutdown_inhibit;
		time_t ss_last_status_change;
		
		service () {};
		service (const service&) = delete;
		~service ();
	};
	
	extern std::list<ioslaves::service*> services_list;
	
		/// Permissions and keys
	struct perms_t {
		bool by_default;
		struct op_perm_t {
			bool authorized;
			std::map<std::string,std::string> props;
		};
		std::map<ioslaves::op_code, op_perm_t> ops;
	};
	std::pair<key_t, perms_t> load_master_key (std::string master);
	void key_save (std::string master, key_t key, std::string perms_conf);
	perms_t::op_perm_t perms_verify_op (const perms_t&, ioslaves::op_code);
	
		/// Services operations
	ioslaves::service* getServiceByName (std::string name);
	void controlService (ioslaves::service* service_stat, bool start, const char* controlling_master);
	extern time_t services_lookup_activity_interval;
	void loadService (std::string name, FILE* service_file);
	void stopAllServices ();
	xif::polyvar serviceStatus (const ioslaves::service* s);
	
		/// Status and stats
	xif::polyvar getStatus (bool full);
	void statusFrame ();
	extern xif::polyvar::map system_stat;
	void statusEnd ();
	
		/// Other operations
	ioslaves::answer_code dns_srv_req (std::function< ioslaves::answer_code(socketxx::io::simple_socket<socketxx::base_netsock>&) >);
	
}

#endif
