/**********************************************************\
 *             ioslaves : Minecraft API service
 *      Common header for service and minecraft-master
 * *********************************************************
 * Copyright © Félix Faisant 2013-2016. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/
	
	// Ioslaves commons
#include "common.hpp"

	// Various
#include <xifutils/polyvar.hpp>
#include <netinet/in.h>
typedef uint16_t ram_mb_t;
#define MC_MAP_PERM 0640
#define MC_LASTSAVETIME_FORCE (time_t)-1
#define MC_LASTSAVETIME_NOSAVE (time_t)0
#define MC_MIN_SERV_RAM (ram_mb_t)512
#define MC_SWAP_FACTOR 0.5f
#define MC_FREE_RAM_FACTOR 0.7f
#define MINECRAFT_SERV_MASTER_MAX_DELAY_CONSIDERED_EQUAL 4
#define MC_JAVA_VM_GC_STAT_HIST_DUR_SEC 100
#define MC_STAT_REFRESH_FREQ_SEC 15

	// Protocol version
#define IOSLAVES_MINECRAFT_PROTO_VERS 0x2A

	// Minecraft service
namespace minecraft {
	
	enum class serv_type : char { VANILLA = 'V', BUKKIT = 'B', FORGE = 'F', CAULDRON = 'L', SPIGOT = 'S', CUSTOM = 'J', BUNGEECORD = 'U' };
	
	enum class op_code : char {
		START_SERVER = 'S',
		REFUSE_OPTION = 'r',
		STOP_SERVER = 's',
		KILL_SERVER = 'k',
		COMM_SERVER = 'C',
		SERV_STAT = 't',
		PERMANENTIZE = 'P',
		FIX_MAP = 'X',
		DELETE_MAP = 'D',
		FTP_SESSION = 'F',
		ASYNC_TRSF = 'A',
		SAVE_MAP = 'M',
	};
	
	enum class serv_op_code : char {
		LIVE_CONSOLE = 'c',
		EXEC_MC_COMMAND = 'x',
	};
	
	enum class transferWhat : char { JAR = 'j', MAP = 'm', SERVFOLD = 's', BIGFILE = 'b' };
	
	enum class whyStopped : char { DESIRED_MASTER = 'M', DESIRED_INTERNAL = 'I', KILLED = 'E', ITSELF = 'i', NOT_STARTED = 'N' };
	
	struct javavm_stat {
		ram_mb_t heap_sz;
		ram_mb_t peak_used, perm_use;
			// over MC_JAVA_VM_GC_STAT_HIST_DUR_SEC
		float gc_pressure;
		uint16_t gc_mean_pause_ms;
			// global
		float gc_glob_pressure;
		float gc_time_ratio;
			// system
		ram_mb_t rss_inst, rss_peak;
		float cpu_inst, cpu_mean;
	};
	
#ifdef IOSLAVESD_MINECRAFT

		// Defs
	#ifndef MINECRAFT_SRV_DIR
		#define MINECRAFT_SRV_DIR "/srv/mc"
	#endif
	#ifndef MINECRAFT_JAR_DIR
		#define MINECRAFT_JAR_DIR MINECRAFT_SRV_DIR"/_jars"
	#endif
	#ifndef MINECRAFT_TEMP_MAP_DIR
		#define MINECRAFT_TEMP_MAP_DIR MINECRAFT_SRV_DIR"/_maps"
	#endif
	#ifndef MINECRAFT_TEMPLATE_SERVMAP_DIR
		#define MINECRAFT_TEMPLATE_SERVMAP_DIR MINECRAFT_SRV_DIR"/_maptpl"
	#endif
	#ifndef MINECRAFT_TEMPLATE_SEV_DIR
		#define MINECRAFT_TEMPLATE_SEV_DIR MINECRAFT_SRV_DIR"/_permtpl"
	#endif
	#ifndef MINECRAFT_BIGFILES_DIR
		#define MINECRAFT_BIGFILES_DIR MINECRAFT_SRV_DIR"/_bigfiles"
	#endif
	#ifndef MINECRAFT_JAVA_USER
		#define MINECRAFT_JAVA_USER "mcjava"
	#endif
	
	extern uid_t java_user_id;
	extern gid_t java_group_id;
	
	extern in_port_t servs_port_range_beg;
	extern uint8_t servs_port_range_sz;
	#define MINECRAFT_PORT_RANGE_BEG servs_port_range_beg
	#define MINECRAFT_PORT_RANGE_SZ servs_port_range_sz
	
	extern in_port_t pure_ftpd_base_port;
	extern in_port_t pure_ftpd_pasv_range_beg;
	extern uint8_t pure_ftpd_max_cli;
	extern pid_t pure_ftpd_pid;
	void ftp_stop_thead (int why);
	void ftp_register_user (std::string username, std::string md5passwd, std::string server, std::string map, time_t validity);
	void ftp_del_sess_for_serv (std::string server, time_t terminal_valididy);
	xif::polyvar ftp_status_for_serv (std::string server);
	
	extern std::string ftp_serv_addr;
#endif

}
