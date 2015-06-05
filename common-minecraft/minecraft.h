/**********************************************************\
 *               -== Xif Network project ==-
 *               ioslaves service : Minecraft
 *          Common header for service and master
 * *********************************************************
 * Copyright © Félix Faisant 2013-2014. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/
	
	// Ioslaves commons
#include "common.hpp"

#ifdef XIFNET
	#define XIFNET_MC_DOM "mc.xif.fr"
#endif
#define MC_MAP_PERM 0640

	// Protocol version
#define IOSLAVES_MINECRAFT_PROTO_VERS 0x20

	// Minecraft service
namespace minecraft {
	
	enum class serv_type : char { VANILLA = 'V', BUKKIT = 'B', FORGE = 'F', CAULDRON = 'L', SPIGOT = 'S', CUSTOM = 'J' };
	
	enum class op_code : char {
		START_SERVER = 'S',
		STOP_SERVER = 's',
		KILL_SERVER = 'k',
		COMM_SERVER = 'C',
		SERV_STAT = 't',
		PERMANENTIZE = 'P',
		DELETE_MAP = 'D',
		FTP_SESSION = 'F',
		ASYNC_TRSF = 'A',
	};
	
	enum class serv_op_code : char {
		LIVE_CONSOLE = 'c',
		EXEC_MC_COMMAND = 'x',
	};
	
	enum class transferWhat : char { JAR = 'j', MAP = 'm', SERVFOLD = 's', BIGFILE = 'b' };
	
	enum class whyStopped : char { DESIRED_MASTER = 'M', DESIRED_INTERNAL = 'I', ERROR_INTERNAL = 'E', ITSELF = 'i', NOT_STARTED = 'N' };
	
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
	#define MINECRAFT_SERV_MASTER_MAX_DELAY_CONSIDERED_EQUAL 4
	#define MINECRAFT_JAVA_USER "mcjava"
	
	extern uid_t java_user_id;
	extern gid_t java_group_id;
	
	extern in_port_t servs_port_range_beg, servs_port_range_sz;
	#define MINECRAFT_PORT_RANGE_BEG servs_port_range_beg
	#define MINECRAFT_PORT_RANGE_SZ servs_port_range_sz
	
	extern in_port_t pure_ftpd_base_port;
	extern in_port_t pure_ftpd_pasv_range_beg;
	extern uint8_t pure_ftpd_max_cli;
	extern pid_t pure_ftpd_pid;
	void ftp_stop_thead (int why);
	void ftp_register_user (std::string username, std::string md5passwd, std::string server, std::string map, time_t validity);
	void ftp_del_sess_for_serv (std::string server);
	
	extern std::string ftp_serv_addr;
#endif

}
