/**********************************************************\
 *                 -== Xif Network project ==-
 *                 ioslaves master : Minecraft
 *   Masters control program for for Minecraft API service
 * *********************************************************
 * Copyright © Félix Faisant 2013-2014. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Commons
#define IOSLAVES_MASTER_FINAL
#include "master.hpp"
#include "minecraft.h"

	// Other
#include <iostream>
#include <algorithm>
#include <sys/dir.h>
#include <sys/time.h>
#include <sys/wait.h>

	// Files
#ifndef IOSLAVES_MINECRAFT_MASTER_DIR
	#define IOSLAVES_MINECRAFT_MASTER_DIR _s(IOSLAVES_MASTER_DIR,"/minecraft")
#endif
#define IOSLAVES_MINECRAFT_MASTER_TEMPAMP_DIR _s(IOSLAVES_MINECRAFT_MASTER_DIR,"/_maps")
#define IOSLAVES_MINECRAFT_MASTER_JAR_DIR _s(IOSLAVES_MINECRAFT_MASTER_DIR,"/_jars")
#define IOSLAVES_MINECRAFT_MASTER_BIGFILES_DIR _s(IOSLAVES_MINECRAFT_MASTER_DIR,"/_bigfiles")

	// Network
#include <socket++/base_unixsock.hpp>
#include <socket++/handler/socket_client.hpp>
#include <socket++/handler/socket_server.hpp>
#include <socket++/quickdefs.h>

	// Websockets
#include <nopoll.h>

	// Exit
int _exit_failure_code = 29;
#undef EXIT_FAILURE
#define EXIT_FAILURE _exit_failure_code
#define EXCEPT_ERROR_IGNORE (ioslaves::answer_code)-1

	// minecraft-master's option variables
bool $granmaster;
std::string $master_id;
std::string $slave_id;
std::string $server_name;
minecraft::serv_type $start_serv_type;
std::string $start_jar_ver;
bool $start_is_perm;
std::string $start_map;
bool $start_earlyconsole = false;
std::string $forced_file;
bool $verify_serv_exists = true;
bool $locked = false;
in_port_t $websocket_port = 0;
noPollConn* $websocket_conn = NULL;
bool $refuse_save = false;
iosl_dyn_slaves::ram_megs_t $needed_ram = 1024;
iosl_dyn_slaves::proc_power_t $needed_cpu = 1.0f;
iosl_dyn_slaves::efficiency_ratio_t $needed_eff = iosl_dyn_slaves::efficiency_ratio_t::REGARDLESS;
time_t $needed_time = 0;
bool $need_quickly = false;
std::string $ftp_user, $ftp_hash_passwd;
uint8_t $mc_viewdist = 7;
time_t $autoclose_time = (time_t)-1;
timeval $connect_timeout = {2,500000};
timeval $comm_timeout = {5,000000};
timeval $op_timeout = {10,000000};

	// minecraft-master's core functionnality functions
time_t getLastSaveTime (std::string serv, std::string map);
void handleReportRequest (socketxx::io::simple_socket<socketxx::base_socket> sock, std::string slave);
void acceptFileSave (socketxx::io::simple_socket<socketxx::base_socket> sock, std::string servname, std::string mapname, std::string slave);
std::string getRunningOnSlave (std::string server);
void setRunningOnSlave (std::string server, std::string running_on_slave);
void verifyMapList (std::string slave_id, std::string server_name, socketxx::io::simple_socket<socketxx::base_socket> sock);
socketxx::io::simple_socket<socketxx::base_socket> getConnection (std::string slave, std::string servname, minecraft::op_code opp, timeval timeout, bool autostart = false);
	void MServPre ();
		void MServStart ();
		void MServStop ();
		void MServStatus ();
		void MServPerm ();
		void MServDelMap ();
		void MServCreate ();
		void MServConsole ();
		void MServFTPSess ();
	void MServPost(ioslaves::answer_code);
void MPost (ioslaves::answer_code);

	// Commmand line arguments
#define OPTCTX_IMPL

#define OPTCTX_POSTFNCT_EXCEPT_T ioslaves::answer_code
#define OPTCTX_POSTFNCT_EXCEPT_DEFAULT (ioslaves::answer_code)0

#define OPTCTX_CTXS                              mcserv                   , servStart        , servStop        , servCreate        , servStatus        , servPerm        , servConsole        , servDelMap        , servFTPSess
#define OPTCTX_PARENTS                           ROOT                     , mcserv           , mcserv          , mcserv            , mcserv            , mcserv          , mcserv             , mcserv            , mcserv
#define OPTCTX_PARENTS_NAMES  "action"         , "server action"          , NULL             , NULL            , NULL              , NULL              , NULL            , NULL               , NULL              , NULL
#define OPTCTX_PARENTS_FNCTS  CTXFP(NULL,MPost), CTXFP(MServPre,MServPost), CTXFO(MServStart), CTXFO(MServStop), CTXFO(MServCreate), CTXFO(MServStatus), CTXFO(MServPerm), CTXFO(MServConsole), CTXFO(MServDelMap), CTXFO(MServFTPSess)
#define OPTCTX_NAMES                             "--server"               , "--start"        , "--stop"        , "--create"        , "--status"        , "--permanentize", "--console"        , "--del-map"       , "--ftp-sess"

#define OPTCTX_PROG_NAME "minecraft-master"
#include <xifutils/optctx.hpp>

inline void tryParseMasterID (int argc, char* const argv[]) {
	if (not $master_id.empty()) return;
	if (argc == optind || argv[optind][0] == '-') 
		return;
	$master_id = argv[optind++];
	if (!ioslaves::validateSlaveName($master_id)) 
		try_help("minecraft-master: invalid master ID\n");
}
inline void testMasterID () {
	if ($master_id.empty())
		try_help("minecraft-master: master ID requiered\n");
}
inline void tryParseSlaveID (int argc, char* const argv[]) {
	if (not $slave_id.empty()) return;
	if (argc == optind || argv[optind][0] == '-') 
		return;
	$slave_id = argv[optind++];
	if (!ioslaves::validateHostname($slave_id)) 
		try_help("minecraft-master: invalid slave ID\n");
}

	// WebLog
#include <sstream>
class cwlog_buf : public std::stringbuf {
public:
	virtual int sync() {
		if (this->str().empty()) return 0;
		if ($websocket_conn != NULL) {
			int rs; errno = 0;
			rs = nopoll_conn_send_text($websocket_conn, this->str().c_str(), this->str().length());
			if (rs != (int)this->str().length()) {
				nopoll_conn_close($websocket_conn);
				$websocket_conn = NULL;
				std::cerr << LOG_AROBASE_ERR << "WebLog stopped : Websocket error : " << ::strerror(errno) << std::endl;
			}
		}
		if (optctx::interactive) std::cerr << this->str() << std::endl;
		else                     std::cerr << this->str() << "<br/>" << std::flush;
		this->str(std::string());
		return 0;
	}
} _cwlog_buf;
std::ostream __log__ (&_cwlog_buf);

pthread_mutex_t xlog::logstream_impl::mutex = PTHREAD_MUTEX_INITIALIZER;
std::ostringstream xlog::logstream_impl::stream;
bool _log_wait_flag = false;
void xlog::logstream_impl::log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid) noexcept {
	if (_log_wait_flag and not (m & LOG_ADD)) ::__log__ << std::flush;
	_log_wait_flag = false;
	switch (lvl) {
		case log_lvl::LOG: case log_lvl::NOTICE: case log_lvl::IMPORTANT: case log_lvl::MAJOR: break;
		case log_lvl::FATAL: case log_lvl::ERROR: case log_lvl::OOPS: ::__log__ << COLOR_RED << "Error : " << COLOR_RESET; break;
		case log_lvl::WARNING: ::__log__ << COLOR_YELLOW << "Warning : " << COLOR_RESET; break;
		case log_lvl::DONE: return; ::__log__ << COLOR_GREEN << "Done ! " << COLOR_RESET; break;
	}
	::__log__ << msg;
	if (m & LOG_WAIT) { _log_wait_flag = true; ::__log__ << ' '; } 
	else ::__log__ << std::flush;
}

	// Main
int main (int argc, char* const argv[]) {
	int r;
	
	::tryParseMasterID(argc,argv);
	::tryParseSlaveID(argc,argv);
	
	struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"no-interactive", no_argument, NULL, 'i'},
		{"granmaster", no_argument, NULL, 'G'},
		{"websocket", required_argument, NULL, 'w'},
		{"refuse-save", no_argument, NULL, 'r'},
		{"server", required_argument, NULL, 'C'},
			{"start", no_argument, NULL, 's'},
				{"bukkit", required_argument, NULL, (char)minecraft::serv_type::BUKKIT},
				{"vanilla", required_argument, NULL, (char)minecraft::serv_type::VANILLA},
				{"forge", required_argument, NULL, (char)minecraft::serv_type::FORGE},
				{"cauldron", required_argument, NULL, (char)minecraft::serv_type::CAULDRON},
				{"spigot", required_argument, NULL, (char)minecraft::serv_type::SPIGOT},
				{"customjar", required_argument, NULL, (char)minecraft::serv_type::CUSTOM},
				{"temp-map", required_argument, NULL, 'm'},
				{"perm-map", required_argument, NULL, 'p'},
				{"map-file", required_argument, NULL, 'z'},
				{"ram", required_argument, NULL, 'a'},
				{"cpu", required_argument, NULL, 'u'},
				{"duration", required_argument, NULL, 'd'},
				{"autoclose", required_argument, NULL, 'j'},
				{"viewdist", required_argument, NULL, 'e'},
				{"quickly", no_argument, NULL, 'q'},
			{"stop", no_argument, NULL, 'o'},
			{"status", no_argument, NULL, 't'},
			{"permanentize", no_argument, NULL, 'P'},
			{"del-map", required_argument, NULL, 'D'},
			{"console", no_argument, NULL, 'l'},
			{"ftp-sess", required_argument, NULL, 'f'},
			{"create", no_argument, NULL, 'c'},
		{NULL, 0, NULL, 0}
	};
	
	int opt, opt_charind = 0;
	while ((opt = ::getopt_long(argc, argv, "-hiGw:r", long_options, &opt_charind)) != -1) {
		switch (opt) {
			case 'h':
				::puts("minecraft-master | ioslaves-master warper program for controling Minecraft service\n"
						 "Usage: minecraft-master MASTER-ID (--granmaster [SLAVE-ID])|(SLAVE-ID) --server=NAME --ACTION\n"
						 "\n"
						 "General options :\n"
						 "  -i, --no-interactive        Enbale HTML log and JSON outputs\n"
						 "  -G, --granmaster            Automagically manage slaves (start, stop, move...)\n"
						 "  -w, --websocket=PORT        Wait a websocket client on PORT before executing commands and\n"
						 "                               output log via this websocket client. Used also for live-console\n"
						 "  -r, --refuse-save           Refuse incoming requests for saving map\n"
						 "\n"
						 "  --server=NAME               Control the Minecraft server named [NAME]. Mandatory.\n"
						 "      Server Actions :\n"
						 "        --start PARAMS          Start the server. Jar and map parameters are requiered\n"
						 "                                and must be each unique.\n"
						 "            Start Parameters :\n"
						 "              --[bukkit|vanilla|forge|spigot|cauldron]=VER | --customjar=NAME\n"
						 "                                  Launch Minecraft with this .jar\n"
						 "                                  Custom jar must be in server folder\n"
						 "              --temp-map=NAME | --perm-map=NAME\n"
						 "                                  Launch temporary map (the server folder will be deleted\n"
						 "                                   at stop) or permanent map (folder will be updated on\n"
						 "                                   server or granmaster if older or newer than master's one).\n"
						 "                  --map-file=PATH   Use this zip for updating slave's server folder or temp map.\n"
						 "                                     Zipped dir must have the same name than the map.\n"
						 "                                     Use it for starting server with an old save of a perm map.\n"
						 "              --duration=TIME     Server running duration, in seconds. Must be a good estimation.\n"
						 "            Optional :\n"
						 "              --autoclose=TIME    Server will close after TIME sec. without players.\n"
						 "                                   Default = --duration; 0 = disabled\n"
						 "              --viewdist=CHUNKS   Minecraft view distance. Default = 7\n"
						 "            Slave selection :\n"
						 "              --cpu=CPU           Needed CPU, using CPU unit (1.0 = Core2Duo E4400).\n"
						 "              --ram=MEGS          Needed memory, in megabytes.\n"
						 "              --quickly           Select slave for speed of server startup\n"
						 "        --stop                  Stop the server.\n"
						 "        --status                Refresh status of the server in database\n"
						 "        --permanentize          Mark map as permanent (will not be deleted at server stop)\n"
						 "        --del-map=NAME          Delete the folder of the map [NAME] of the server\n"
						 "        --console               Bind the connection to the server's LiveConsole. If used at\n"
						 "                                 after server start action, early LiveConsole is activated.\n"
						 "        --ftp-sess=USER:HASHPW  Create new FTP session for running map for user USER and\n"
						 "                                 hashed password HASHPW. Returns ADDR:PORT of the FTP server.\n"
						 "        --create                Create a new server in database\n"
						 );
				return EXIT_SUCCESS;
			case 'i':
				optctx::interactive = false;
				::tryParseMasterID(argc,argv);
				::tryParseSlaveID(argc,argv);
				break;
			case 'G':
				::testMasterID();
				if (not $slave_id.empty())
					try_help("unexcepted --granmaster after slave ID\n");
				$granmaster = true;
				::tryParseSlaveID(argc,argv);
					// Create ioslaves-master and minecraft-matser dirs if not exist
				r = ::access(_s(IOSLAVES_MASTER_DIR), F_OK);
				if (r == -1) {
					r = ::mkdir(_s(IOSLAVES_MASTER_DIR), 0740);
					if (r == -1) {
						std::cerr << COLOR_RED << "Can't create ioslaves-master directory" << COLOR_RESET << " (" << IOSLAVES_MASTER_DIR << ") : " << ::strerror(errno) << std::endl;
						return EXIT_FAILURE;
					}
					goto _create_minecraft_dir;
				} else {
					r = ::access(_s(IOSLAVES_MINECRAFT_MASTER_DIR), F_OK);
					if (r == -1) {
					_create_minecraft_dir:
						r = ::mkdir(_s(IOSLAVES_MINECRAFT_MASTER_DIR), 0740);
						if (r == -1) {
							std::cerr << COLOR_RED << "Can't create minecraft-matser directory" << COLOR_RESET << " (" << IOSLAVES_MINECRAFT_MASTER_DIR << ") : " << ::strerror(errno) << std::endl;
							return EXIT_FAILURE;
						}
					}
				}
				break;
			case 'w': {
				std::string wsockport = optarg;
				try {
					$websocket_port = ::atoix<in_port_t>(wsockport, IX_DEC);
				} catch (...) {
					try_help("--websocket : invalid port\n");
				}
				::tryParseMasterID(argc,argv);
				::tryParseSlaveID(argc,argv);
			} break;
			case 'r':
				$refuse_save = true;
				break;
			case 'C':
				::testMasterID();
				if (not $granmaster and $slave_id.empty()) 
					try_help("Not in granmaster mode : slave ID must be defined");
				optctx::optctx_set(optctx::mcserv);
				$server_name = optarg;
				if (!ioslaves::validateName($server_name))
					try_help("--server: invalid server name\n");
				break;
			case 's':
				optctx::optctx_set(optctx::servStart);
				break;
			case (char)minecraft::serv_type::VANILLA:
			case (char)minecraft::serv_type::BUKKIT:
			case (char)minecraft::serv_type::FORGE:
			case (char)minecraft::serv_type::SPIGOT:
			case (char)minecraft::serv_type::CAULDRON:
			case (char)minecraft::serv_type::CUSTOM:
			{	const char* servtype = NULL;
				for (size_t i = 0; long_options[i].name != NULL; i++) 
					if (long_options[i].val == opt) 
						servtype = long_options[i].name;
				optctx::optctx_test(servtype, optctx::servStart);
				$start_serv_type = (minecraft::serv_type)opt;
				$start_jar_ver = optarg;
				try {
					ioslaves::version($start_jar_ver, true);
				} catch (std::exception& e) { try_help(_s("jar: invalid version str : ",e.what(),"\n")); }
			} break;
			case 'm':
				optctx::optctx_test("--temp-map", optctx::servStart);
				$start_is_perm = false;
				$start_map = optarg;
				if (!ioslaves::validateName($start_map))
					try_help("--temp-map: invalid map name\n");
				break;
			case 'p':
				optctx::optctx_test("--perm-map", optctx::servStart);
				$start_is_perm = true;
				$start_map = optarg;
				if (!ioslaves::validateName($start_map))
					try_help("--perm-map: invalid map name\n");
				break;
			case 'z':
				$forced_file = optarg;
				r = ::access(optarg, R_OK);
				if (r == -1) {
					::fputs("--map-file: can't access file", stderr);
					return EXIT_FAILURE;
				}
				break;
			case 'a':
				optctx::optctx_test("--ram", optctx::servStart);
				try {
					$needed_ram = ::atoix<uint16_t>(optarg, IX_DEC);
				} catch (...) {
					try_help("--ram : invalid mem quantity\n");
				}
				break;
			case 'u': {
				optctx::optctx_test("--cpu", optctx::servStart);
				double f = ::atof(optarg);
				if (f == 0.0f or f <= 0.0f or f > 50.f)
					try_help("--cpu : invalid cpu quantity\n");
				$needed_cpu = (float)f;
			} break;
			case 'd':
				optctx::optctx_test("--duration", optctx::servStart);
				try {
					$needed_time = ::atoix<uint32_t>(optarg);
				} catch (...) {
					try_help("--duration : invalid param\n");
				}
				break;
			case 'e':
				optctx::optctx_test("--viewdist", optctx::servStart);
				try {
					$mc_viewdist = ::atoix<uint8_t>(optarg);
				} catch (...) {
					try_help("--viewdist : invalid view distance\n");
				}
				break;
			case 'j':
				optctx::optctx_test("--autoclose", optctx::servStart);
				try {
					$autoclose_time = ::atoix<uint32_t>(optarg);
				} catch (...) {
					try_help("--autoclose : invalid time\n");
				}
				break;
			case 'q':
				optctx::optctx_test("--quickly", optctx::servStart);
				$need_quickly = true;
				break;
			case 'o':
				optctx::optctx_set(optctx::servStop);
				break;
			case 't':
				optctx::optctx_set(optctx::servStatus);
				break;
			case 'P':
				optctx::optctx_set(optctx::servPerm);
				break;
			case 'f': {
				optctx::optctx_set(optctx::servFTPSess);
				std::string usr = optarg;
				size_t dotpos = usr.find_first_of(':');
				if (dotpos == 0 or dotpos == std::string::npos) 
					try_help("--ftp-sess : invalid arg\n");
				$ftp_user = usr.substr(0, dotpos);
				if ($ftp_user.empty()) 
					try_help("--ftp-sess : invalid user name\n");
				$ftp_hash_passwd = usr.substr(dotpos+1, std::string::npos);
				if (not ioslaves::validateHexa($ftp_hash_passwd) or $ftp_hash_passwd.length() != 32) 
					try_help("--ftp-sess : invalid md5 password hex hash\n");
			} break;
			case 'D':
				optctx::optctx_set(optctx::servDelMap);
				$start_map = optarg;
				if (!ioslaves::validateName($start_map))
					try_help("--del-map: invalid map name\n");
				break;
			case 'l':
				if (optctx::optctx == optctx::servStart) {
					if ($websocket_port == 0) 
						try_help("--start with --console : --websocket=PORT must be used\n");
					$start_earlyconsole = true;
				} else
					optctx::optctx_set(optctx::servConsole);
				break;
			case 'c':
				optctx::optctx_set(optctx::servCreate);
				$verify_serv_exists = false;
				if (!$granmaster)
					try_help("--create: only valid in granmaster mode\n");
				break;
			default: 
				try_help();
		}
	}
	optctx::optctx_end();
	if (optctx::optctx == optctx::servStart) {
		if ($start_map.empty()) 
			try_help("--start : a map parameter (--perm-map or --temp-map) must be defined\n");
		if ($start_jar_ver.empty()) 
			try_help("--start : a jar parameter (--bukkit, --vanilla, ...) must be defined\n");
		if ($needed_time == 0) 
			try_help("--start : server running duration (--duration) must be defined\n");
	}
	
	RAII_AT_END_N(lck,{
		if ($locked)
			::unlink(_s( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/_mcmaster.lock" ));
	});
	
	noPollCtx* wsctx = NULL;
	RAII_AT_END_N(ws,{
		if ($websocket_conn != NULL) nopoll_conn_close($websocket_conn);
		if (wsctx != NULL) nopoll_ctx_unref(wsctx);
		nopoll_cleanup_library();
	});
	if ($websocket_port != 0) {
		std::cerr << LOG_AROBASE << "WebLog : Waiting for the websocket client on port " << $websocket_port << "..." << std::endl;
		std::string lockpath = _S( IOSLAVES_MINECRAFT_MASTER_DIR,"/_websock.lock" );
		if ($granmaster)
		for (uint counter = 0; ; counter++) {
			if (counter == 2) {
				__log__ << NICE_WARNING << "Websocket lock file was locked for 2 seconds." << std::flush;
				EXIT_FAILURE = EXIT_FAILURE_COMM;
				return EXIT_FAILURE;
			}
			fd_t f = ::open(lockpath.c_str(), O_CREAT|O_RDONLY|O_EXCL|O_NOFOLLOW, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
			if (f == -1 and errno == EEXIST) {
				::sleep(1);
				continue;
			}
			if (f == -1) throw xif::sys_error("create lock file");
			::close(f);
			break;
		}
		else lockpath.clear();
		RAII_AT_END_N(ws_lock, {
			if (not lockpath.empty())
				::unlink(lockpath.c_str());
		});
		wsctx = nopoll_ctx_new();
		if (wsctx == NULL) {
			std::cerr << LOG_AROBASE_ERR << "Failed to create websocket context" << std::endl; EXIT_FAILURE = EXIT_FAILURE_COMM; return EXIT_FAILURE; }
		noPollConn* listener = nopoll_listener_new(wsctx, "0.0.0.0", ::ixtoa($websocket_port).c_str());
		if (not nopoll_conn_is_ok(listener)) {
			std::cerr << LOG_AROBASE_ERR << "Failed to create listening websocket" << std::endl; EXIT_FAILURE = EXIT_FAILURE_COMM; return EXIT_FAILURE; }
		struct _noPoll_callbacks {
			static nopoll_bool onConnReady (noPollCtx* wsctx, noPollConn* conn, void* data) {
				if ($websocket_conn != NULL) return false;
				std::cerr << LOG_AROBASE_OK << "Websocket client is here !" << std::endl;
				nopoll_conn_send_text(conn, "Hello websocket client !", -1);
				return true;
			}
			static void onMsg (noPollCtx* wsctx, noPollConn* conn, noPollMsg* msg, noPollPtr data) {
				nopoll_loop_stop(wsctx);
				$websocket_conn = conn;
				std::string str ((const char*)nopoll_msg_get_payload(msg), nopoll_msg_get_payload_size(msg));
				nopoll_msg_unref(msg);
				std::cerr << LOG_AROBASE_OK << "'" << str << "' received" << std::endl;
				throw std::exception();
			}
		};
		nopoll_ctx_set_on_ready(wsctx, &_noPoll_callbacks::onConnReady, NULL);
		nopoll_ctx_set_on_msg(wsctx, &_noPoll_callbacks::onMsg, NULL);
		try {
			nopoll_loop_wait(wsctx, 1500000);
		} catch (std::exception) {}
		nopoll_conn_close(listener);
		if ($websocket_conn == NULL) {
			std::cerr << LOG_AROBASE_ERR << "Can't get websocket client..." << std::endl;
			EXIT_FAILURE = EXIT_FAILURE_COMM;
			return EXIT_FAILURE;
		}
	}
	
		// Execute
	try {
		optctx::optctx_exec();
	} catch (OPTCTX_POSTFNCT_EXCEPT_T) {
		return EXIT_FAILURE;
	} catch (xif::sys_error& se) {
		__log__ << NICE_WARNING << COLOR_RED << "System error" << COLOR_RESET << " : " << se.what() << std::flush;
		return EXIT_FAILURE;
	} catch (socketxx::error& ne) {
		__log__ << NICE_WARNING << COLOR_RED << "Network error" << COLOR_RESET << " : " << ne.what() << std::flush;
		return EXIT_FAILURE;
	} catch (std::runtime_error& re) {
		__log__ << NICE_WARNING << COLOR_RED << "Error" << COLOR_RESET << " : " << re.what() << std::flush;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
	
}

	/********** Core **********/

	// Save time functions
time_t getLastSaveTime (std::string serv, std::string map) {
	time_t lastsavetime = 0;
	DIR* map_dir = ::opendir( _s(IOSLAVES_MINECRAFT_MASTER_DIR,"/",serv,"/maps/",map) );
	if (map_dir == NULL) {
		if (errno == ENOENT) return (time_t)0;
		throw xif::sys_error("can't open server map save folder for listing");
	}
	dirent* dp = NULL;
	while ((dp = ::readdir(map_dir)) != NULL) {
		if (::strlen(dp->d_name) < map.length()+6) 
			continue;
		size_t ni, ei;
		for (ni = 0; ni < map.length(); ni++) 
			if (dp->d_name[ni] != map[ni]) 
				continue;
		if (dp->d_name[ni++] != '_') continue;
		for (ei = 1; ei <= 4; ei++)
			if (dp->d_name[::strlen(dp->d_name)-ei] != ".zip"[4-ei]) 
				continue;
		std::string timestamp = std::string(dp->d_name).substr(ni, ::strlen(dp->d_name)-map.length()-5);
		try {
			time_t savetime = ::atoix<time_t>(timestamp, IX_HEX);
			if (savetime > lastsavetime) lastsavetime = savetime;
		} catch (std::runtime_error) { continue; }
	}
	::closedir(map_dir);
	return lastsavetime;
}

	// Launch ioslaves-master and connect
socketxx::io::simple_socket<socketxx::base_socket> getConnection (std::string slave, std::string servname, minecraft::op_code opp, timeval timeout, bool autostart) {
	bool secondtry = false;
	std::function<socketxx::io::simple_socket<socketxx::base_socket>(void)> get_sock = [&]() -> socketxx::io::simple_socket<socketxx::base_socket> {
		try {
			try {
				__log__ << LOG_ARROW << "Connecting to '" << slave << "'..." << std::flush;
				return iosl_master::slave_api_service_connect(slave, $master_id, "minecraft", $connect_timeout);
			} catch (ioslaves::answer_code& answ) {
				if (answ == ioslaves::answer_code::BAD_STATE and $granmaster) {
					__log__ << LOG_ARROW << "Minecraft service seems to be off. Starting it..." << std::flush;
					socketxx::simple_socket_client<socketxx::base_netsock> sock = iosl_master::slave_connect(slave, 0);
					iosl_master::slave_command(sock, $master_id, ioslaves::op_code::SERVICE_START);
					sock.o_str("minecraft");
					answ = (ioslaves::answer_code)sock.i_char();
					if (answ != ioslaves::answer_code::OK) 
						throw answ;
				} else throw answ;
				return iosl_master::slave_api_service_connect(slave, $master_id, "minecraft", $connect_timeout);
			}
		} catch (master_err& e) {
			__log__ << LOG_ARROW_ERR << "ioslaves-master error : " << e.what() << std::flush;
			if (e.down and not secondtry and autostart and $granmaster) {
				time_t time_up = 0;
				try {
					time_up = iosl_master::slave_start($slave_id, $master_id);
				} catch (std::exception& e) {
					__log__ << LOG_AROBASE_ERR << "Power up error : " << e.what() << std::flush;
					EXIT_FAILURE = EXIT_FAILURE_CONN;
					throw EXCEPT_ERROR_IGNORE;
				}
				__log__ << LOG_AROBASE_ERR << "Please wait " << time_up << "s for slave starting..." << std::flush;
				::sleep((uint)time_up);
				secondtry = true;
				return get_sock();
			} else {
				EXIT_FAILURE = EXIT_FAILURE_CONN;
				throw EXCEPT_ERROR_IGNORE;	
			}
		}
	};
	socketxx::io::simple_socket<socketxx::base_socket> sock = get_sock();
	sock.set_read_timeout($comm_timeout);
	timeval utc_time; ::gettimeofday(&utc_time, NULL);
	time_t slave_time = sock.i_int<int64_t>();
	time_t diff;
	if ((diff = ::abs((int)(utc_time.tv_sec - slave_time))) > IOSLAVES_MASTER_MAX_UTC_DIFF_TIME) {
		__log__ << NICE_WARNING << "Time diff between slave and master (" << diff << "s) is bigger than " << IOSLAVES_MASTER_MAX_UTC_DIFF_TIME << "s" << std::flush;
		EXIT_FAILURE = EXIT_FAILURE_COMM;
		throw EXCEPT_ERROR_IGNORE;
	}
	uint16_t dist_proto_vers = sock.i_int<uint16_t>();
	if (dist_proto_vers != IOSLAVES_MINECRAFT_PROTO_VERS) {
		__log__ << NICE_WARNING << "Distant protocol version (" << ::ixtoa(dist_proto_vers,IX_HEX) << ") != local protocol version (" << ::ixtoa(IOSLAVES_MINECRAFT_PROTO_VERS,IX_HEX) << ")" << std::flush;
		EXIT_FAILURE = EXIT_FAILURE_COMM;
		throw EXCEPT_ERROR_IGNORE;
	}
	sock.o_bool($granmaster);
	sock.o_str(servname);
	sock.o_char((char)opp);
	sock.set_read_timeout(timeval({120,0}));
	ioslaves::answer_code o;
	while ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) {
		if (o == ioslaves::answer_code::WANT_REPORT)
			handleReportRequest(sock, slave);
		else throw o;
	}
	__log__ << "Opp '" << (char)opp << "' accepted by distant minecraft service" << std::flush;
	sock.set_read_timeout($op_timeout);
	return sock;
}

	// Retrieve server folder save
void acceptFileSave (socketxx::io::simple_socket<socketxx::base_socket> sock, std::string servname, std::string mapname, std::string slave) {
	__log__ << LOG_AROBASE << "Accepting server folder save of map '" << mapname << "' for server '" << servname << "'" << std::flush;
	std::string folder_saves = _S( IOSLAVES_MINECRAFT_MASTER_DIR,"/",servname,"/maps/",mapname );
	int r;
	time_t lastsavetime_dist = sock.i_int<int64_t>();
	time_t lastsavetime_local = getLastSaveTime(servname, mapname);
	if ($refuse_save and not $forced_file.empty()) {
		__log__ << LOG_AROBASE_ERR << "Won't accept save : refuse option activated" << std::flush;
		sock.o_bool(false);
		return;
	}
	if (lastsavetime_dist < lastsavetime_local) {
		__log__ << LOG_AROBASE_ERR << "Won't accept save : distant save (" << lastsavetime_dist << ") is older than last local save (" << lastsavetime_local << ")" << std::flush;
		sock.o_bool(false);
		return;
	}
	std::string finalpath = _S( folder_saves,'/',mapname,'_',::ixtoa(lastsavetime_dist,IX_HEX_MAJ),".zip" );
	if (::access(finalpath.c_str(), F_OK) == 0) {
		__log__ << LOG_AROBASE_ERR << "Won't accept save : already exists for " << lastsavetime_local << std::flush;
		sock.o_bool(false);
		return;
	}
	sock.o_bool(true);
	std::string tmpfn;
	tmpfn = sock.i_file(_S( IOSLAVES_MASTER_DIR,"/ioslaves-mc-master-getmap" ));
	r = ::mkdir(folder_saves.c_str(), S_IRWXU|S_IRWXG);
	if (r == -1 and errno != EEXIST and errno != EISDIR) 
		throw xif::sys_error("can't create server map dir");
	r = ::rename(tmpfn.c_str(), finalpath.c_str());
	if (r == -1) 
		throw xif::sys_error("can't move save to server maps dir");
	ioslaves::infofile_set(_s(folder_saves,"/lastsave_from"), slave);
	ioslaves::infofile_set(_s(folder_saves,"/lastsave"), ::ixtoa(lastsavetime_dist));
	ioslaves::infofile_set(_s(folder_saves,"/truesave"), "true");
	__log__ << LOG_AROBASE_OK << "Accepting done ! Save set as true save from " << slave << std::flush;
}

	// Process a report request (stopping, crashing...) of slave
void handleReportRequest (socketxx::io::simple_socket<socketxx::base_socket> sock, std::string slave) {
	int r;
	std::string servname = sock.i_str();
	__log__ << LOG_AROBASE << "Handling stop report request for server '" << servname << "' from slave " << slave << "..." << std::flush;
	minecraft::whyStopped why_stopped = (minecraft::whyStopped)sock.i_char();
	bool gracefully_stopped = sock.i_bool();
	std::string map_to_save = sock.i_str();
	if (not $granmaster) {
		__log__ << LOG_AROBASE_ERR << "Refusing report request : not granmaster" << std::flush;
		sock.o_bool(false);
		return;
	}
	std::string map_path = _S( IOSLAVES_MINECRAFT_MASTER_DIR,'/',servname,"/maps/",map_to_save );
	r = ::access( _s(IOSLAVES_MINECRAFT_MASTER_DIR,'/',servname), X_OK);
	if (r == -1) {
		__log__ << LOG_AROBASE_ERR << "Can't accept report request : unable to access server folder" << std::flush;
		sock.o_bool(false);
		return;
	}
	if (not map_to_save.empty()) {
		r = ::mkdir(map_path.c_str(), S_IRWXU|S_IRWXG);
		if (r == -1 && errno != EEXIST) {
			__log__ << NICE_WARNING << COLOR_YELLOW << "Warning !" << COLOR_RESET << " Can't create map folder " << map_to_save << " for accepting map save : " << ::strerror(errno) << std::flush;
			sock.o_bool(false);
			return;
		}
		ioslaves::infofile_set(_s(map_path,"/truesave"), "false");
		__log__ << "True save : false" << std::flush;
	}
	__log__ << "Server was stopped " << (gracefully_stopped?"":"un") << "gracefully. Reason : " << (char)why_stopped << ". Updating state..." << std::flush;
	if (::getRunningOnSlave(servname).empty())
		__log__ << COLOR_YELLOW << "Warning ! Locally, server was stopped. Maybe an another master started this server. " << COLOR_RESET << std::flush;
	::setRunningOnSlave(servname, "");
	sock.o_bool(true);
	if (not map_to_save.empty()) 
		acceptFileSave(sock, servname, map_to_save, slave);
	__log__ << LOG_AROBASE_OK << "Report request : Done" << std::flush;
}

void MServPre () {
	int r;
	if ($granmaster) {
		r = ::access( _s(IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name), X_OK);
		if (r == -1 and errno != ENOENT) 
			throw xif::sys_error("can't test for presence of client dir");
		if (r == 0 and $verify_serv_exists == false) {
			__log__ << LOG_ARROW_ERR << "Server '" << $server_name << "' already exists !" << std::flush;
			throw EXCEPT_ERROR_IGNORE;
		}
		if (r == -1 and $verify_serv_exists == true) {
			__log__ << LOG_ARROW_ERR << "Server '" << $server_name << "' doesn't exist !" << std::flush;
			throw EXCEPT_ERROR_IGNORE;
		}
		if ($verify_serv_exists == true and $granmaster) {
				// Server Lock
			std::string lockpath = _S( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/_mcmaster.lock" );
			for (uint counter = 0; ; counter++) {
				if (counter == 10) {
					__log__ << NICE_WARNING << "Lock file for server '" << $server_name << "' (" << lockpath << ") was locked for 10 seconds." << std::flush;
					throw EXCEPT_ERROR_IGNORE;
				}
				fd_t f = ::open(lockpath.c_str(), O_CREAT|O_RDONLY|O_EXCL|O_NOFOLLOW, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
				if (f == -1 and errno == EEXIST) {
					if (counter == 0) 
						__log__ << COLOR_YELLOW << "Waiting for lock file..." << COLOR_RESET << std::flush;
					::sleep(1);
					continue;
				}
				if (f == -1) throw xif::sys_error("create lock file");
				::close(f);
				$locked = true;
				break;
			}
		}
	}
}

void MServPost (ioslaves::answer_code e) {
	if (not $granmaster) throw e;
	::unlink(_s( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/_mcmaster.lock" ));
	$locked = false;
	throw e;
}

std::string getRunningOnSlave (std::string serv) {
	std::string filename = _S( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/running_on" );
	std::string running_on_slave = ioslaves::infofile_get(filename.c_str(), false);
	if (not running_on_slave.empty() and !ioslaves::validateSlaveName(running_on_slave))
		throw std::runtime_error("invalid slave name in file 'running_on'");
	return running_on_slave;
}

void setRunningOnSlave (std::string serv, std::string running_on_slave) {
	std::string filename = _S( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/running_on" );
	ioslaves::infofile_set(filename.c_str(), running_on_slave);
}

inline bool checkSlaveStatus (std::string slave) {
	bool isSlaveRunning = iosl_master::slave_test(slave);
	if (not isSlaveRunning) 
		__log__ << "Slave '" << slave << "' is unreachable." << std::flush;
	return isSlaveRunning;
}

void verifyMapList (std::string slave_id, std::string server_name, socketxx::io::simple_socket<socketxx::base_socket> sock) {
	int r;
	try {
		size_t sz = sock.i_int<uint32_t>();
		while (sz --> 0) {
			std::string map = sock.i_str();
			time_t lastsave = sock.i_int<uint64_t>();
			if (not $granmaster) {
				sock.o_char((char)ioslaves::answer_code::OK);
				continue;
			}
			std::string map_folder = _S( IOSLAVES_MINECRAFT_MASTER_DIR,"/",server_name,"/maps/",map );
			bool want_get = false;
			r = ::access(map_folder.c_str(), F_OK);
			if (r == -1) {
				__log__ << COLOR_YELLOW << "Warning !" << COLOR_RESET << " Map '" << map << "' for server '" << server_name << "' on slave '" << slave_id << "' doesn't exist locally !" << std::flush;
				r = ::mkdir(map_folder.c_str(), S_IRWXU|S_IRWXG);
				if (r == -1) {
					__log__ << NICE_WARNING << COLOR_YELLOW << "Warning !" << COLOR_RESET << " Can't create map folder '" << map << "' : " << ::strerror(errno) << std::flush;
					continue;
				}
				ioslaves::infofile_set(_s(map_folder,"/truesave"), "false");
				ioslaves::infofile_set(_s(map_folder,"/lastsave_from"), slave_id);
				__log__ << LOG_AROBASE_OK << "Map folder '" << map << "' created." << std::flush;
				if (lastsave != 0)
					want_get = true;
			} else {
				time_t lastsave_local = getLastSaveTime(server_name, map);
				if (lastsave_local < lastsave) {
					__log__ << COLOR_YELLOW << "Warning !" << COLOR_RESET << " Slave '" << slave_id << "' have a more recent version of map '" << map << "'." << std::flush;
					want_get = true;
				}
			}
			if (want_get and not $refuse_save) {
				__log__ << LOG_AROBASE << "Retrieving map save at " << lastsave << "..." << std::flush;
				sock.o_char((char)ioslaves::answer_code::WANT_GET);
				lastsave = sock.i_int<int64_t>();
				sock.o_bool(true);
				std::string savepath = _S( map_folder,'/',map,'_',::ixtoa(lastsave,IX_HEX_MAJ),".zip" );
				fd_t save_f = ::open(savepath.c_str(), O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW, MC_MAP_PERM);
				if (save_f == -1)
					throw xif::sys_error("can't open map save file");
				RAII_AT_END_L( ::close(save_f) );
				sock.i_file(save_f);
				ioslaves::infofile_set(_s(map_folder,"/lastsave"), ::ixtoa(lastsave));
				ioslaves::infofile_set(_s(map_folder,"/truesave"), "false");
				ioslaves::infofile_set(_s(map_folder,"/lastsave_from"), slave_id);
				__log__ << LOG_AROBASE_OK << "Retrieving done !" << std::flush;
			} else
				sock.o_char((char)ioslaves::answer_code::OK);
		}
	} catch (socketxx::error& e) {
		__log__ << LOG_AROBASE_ERR << "Net error while getting map list for server " << server_name << " : " << e.what() << std::flush;
		return;
	}
}

/** ---------------------------- STATUS ---------------------------- **/

void MServStatus () {
	__log__ << LOG_ARROW << "Updating status for server '" << $server_name << "'..." << std::flush;
	int32_t n_players = -1;
	in_port_t s_port = 0;
	bool s_is_perm_map = true;
	time_t s_time_start = 0;
	std::string s_map = "";
	if ($granmaster) {
		std::string $local_slave_id = ::getRunningOnSlave($server_name);
		if (not $local_slave_id.empty()) {
			__log__ << "Checking on slave '" << $local_slave_id << "' on which server should be running now..." << std::flush;
			bool $status = checkSlaveStatus($local_slave_id);
			if ($status) {
				try {
					auto sock = getConnection($local_slave_id, $server_name, minecraft::op_code::SERV_STAT, {2,0});
					std::string $re_local_slave_id = ::getRunningOnSlave($server_name);
					if ($local_slave_id != $re_local_slave_id) 
						__log__ << "After report, the server is now closed" << std::flush;
					$status = sock.i_bool();
					if ($status) {
						sock.o_bool(true);
						s_is_perm_map = sock.i_bool();
						s_map = sock.i_str();
						s_time_start = sock.i_int<uint64_t>();
						n_players = sock.i_int<int32_t>();
						s_port = sock.i_int<in_port_t>();
					}
					verifyMapList($local_slave_id, $server_name, sock);
				} catch (std::runtime_error& e) {
					__log__ << NICE_WARNING << "Error while connecting to slave : " << e.what() << std::flush;
					$status = false;
				} catch (...) {
					__log__ << NICE_WARNING << "Failed to connect to slave ! " << std::flush;
					$status = false;
				}
			}
			if ($status) {
				__log__ << LOG_ARROW_OK << "Yes, server is running on slave '" << $local_slave_id << "'." << std::flush;
			} else {
				__log__ << LOG_ARROW_ERR << "Erm... No, server isn't running on slave '" << $local_slave_id << "'." << std::flush;
				if (not $slave_id.empty() and $local_slave_id != $slave_id) {
					goto __check_on_user_slave;
				} else {
					__log__ << "Marking as closed..." << std::flush;
					::setRunningOnSlave($server_name, "");
				}
			}
			if (not optctx::interactive)
				std::cout << std::endl << xif::polyvar(xif::polyvar::map({{"running",$status},{"slave",$local_slave_id},{"players",n_players},{"port",s_port},{"is_perm_map",s_is_perm_map},{"map",s_map},{"start_time",s_time_start}})).to_json() << std::endl;
		} else {
			__log__ << "Locally, server is not running." << std::flush;
			if (not $slave_id.empty()) 
				goto __check_on_user_slave;
			if (not optctx::interactive)
				std::cout << std::endl << xif::polyvar(xif::polyvar::map({{"running",false}})).to_json() << std::endl;
		}
		return;
	__check_on_user_slave:
		__log__ << "Trying with slave '" << $slave_id << "'..." << std::flush;
		bool $status = checkSlaveStatus($slave_id);
		if ($status) {
			try {
				auto sock = getConnection($slave_id, $server_name, minecraft::op_code::SERV_STAT, {2,0});
				$status = sock.i_bool();
				if ($status) {
					sock.o_bool(true);
					s_is_perm_map = sock.i_bool();
					s_map = sock.i_str();
					s_time_start = sock.i_int<uint64_t>();
					n_players = sock.i_int<int32_t>();
					s_port = sock.i_int<in_port_t>();
				}
				verifyMapList($slave_id, $server_name, sock);
			} catch (std::runtime_error& e) {
				__log__ << NICE_WARNING << "Error while connecting to slave : " << e.what() << std::flush;
				$status = false;
			} catch (...) {
				__log__ << NICE_WARNING << "Failed to connect to slave ! " << std::flush;
				$status = false;
			}
		}
		if ($status) {
			__log__ << LOG_ARROW_ERR << "Ok, server is running on slave '" << $slave_id << "'. Updating..." << std::flush;
			::setRunningOnSlave($server_name, $slave_id);
			if (s_is_perm_map) {
				__log__ << "True save : false" << std::flush;
				ioslaves::infofile_set(_s(IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/maps/",s_map,"/truesave"), "false");
			}
		} else {
			__log__ << LOG_ARROW_OK << "No, server isn't running on slave '" << $slave_id << "'. You are wrong ^_^ !" << std::flush;
			if (not $local_slave_id.empty()) {
				__log__ << "Marking as closed..." << std::flush;
				::setRunningOnSlave($server_name, "");
			}
		}
		if (not optctx::interactive)
			std::cout << std::endl << xif::polyvar(xif::polyvar::map({{"running",$status},{"slave",$slave_id},{"players",n_players},{"port",s_port},{"is_perm_map",s_is_perm_map},{"map",s_map},{"start_time",s_time_start}})).to_json() << std::endl;
	} else {
		auto sock = getConnection($slave_id, $server_name, minecraft::op_code::SERV_STAT, {2,0});
		bool $status = sock.i_bool();
		if ($status) {
			sock.o_bool(true);
			s_is_perm_map = sock.i_bool();
			s_map = sock.i_str();
			s_time_start = sock.i_int<uint64_t>();
			n_players = sock.i_int<int32_t>();
			s_port = sock.i_int<in_port_t>();
		}
		verifyMapList($slave_id, $server_name, sock);
		__log__ << LOG_ARROW_OK << "Server '" << $server_name << "' on slave '" << $slave_id << "' is " << ($status?"running":"NOT running") << std::flush;
		if ($status) {
			__log__ << n_players << " players connected" << std::flush;
		}
		if (not optctx::interactive)
			std::cout << std::endl << xif::polyvar(xif::polyvar::map({{"running",$status},{"players",n_players},{"port",s_port},{"is_perm_map",s_is_perm_map},{"map",s_map},{"start_time",s_time_start}})).to_json() << std::endl;
	}
}

/** ---------------------------- PERMANENTIZE ---------------------------- **/

void MServPerm () {
	__log__ << LOG_ARROW << "Permanentize map on server " << $server_name << "..." << std::flush;
	if ($granmaster) {
		std::string running_on_slave = ::getRunningOnSlave($server_name);
		if (running_on_slave.empty()) {
			__log__ << LOG_ARROW_ERR << "Server '" << $server_name << "' is (probably) not running !" << std::flush;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		}
		$slave_id = running_on_slave;
	}
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::PERMANENTIZE, {2,0});
	std::string map = sock.i_str();
	ioslaves::answer_code o;
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << LOG_ARROW_OK << "Done on map '" << map << "' !" << std::flush;
	if (not $granmaster) 
		return;
	std::string folder_saves = _S( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",map );
	if (::access(folder_saves.c_str(), F_OK) == 0) {
		__log__ << COLOR_YELLOW << "Map folder '" << map << "' already exists." << COLOR_RESET << " Map will be saved inside !" << std::flush;
	}
}

/** ---------------------------- NEW FTP SESSION ---------------------------- **/

void MServFTPSess () {
	__log__ << LOG_ARROW << "Create FTP session for user '" << $ftp_user << "' on server " << $server_name << " for current running map..." << std::flush;
	if ($granmaster) {
		std::string running_on_slave = ::getRunningOnSlave($server_name);
		if (running_on_slave.empty()) {
			__log__ << LOG_ARROW_ERR << "Server '" << $server_name << "' is (probably) not running !" << std::flush;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		}
		$slave_id = running_on_slave;
	}
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::FTP_SESSION, {2,0});
	sock.o_str($ftp_user);
	sock.o_str($ftp_hash_passwd);
	uint16_t sess_validity = 60*15;
	sock.o_int<uint16_t>(sess_validity);
	ioslaves::answer_code o;
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	std::string addrstr = sock.i_str();
	__log__ << LOG_ARROW_OK << "FTP session created for " << sess_validity << "s. FTP server address : " << addrstr << std::flush;
	if (not optctx::interactive)
	std::cout << std::endl << addrstr;
}

/** ---------------------------- DELETE MAP ---------------------------- **/

void MServDelMap () {
	__log__ << LOG_ARROW << "Delete map '" << $start_map << "' on server " << $server_name << "..." << std::flush;
	if ($slave_id.empty()) {
		std::string lastsave_from = ioslaves::infofile_get(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",$start_map,"/lastsave_from" ), true);
		if (lastsave_from.empty() or !ioslaves::validateSlaveName(lastsave_from)) {
			__log__ << LOG_ARROW_ERR << "No info about slave which would have the map on." << std::flush;
			return;
		}
		$slave_id = lastsave_from;
	}
	__log__ << "Trying on " << $slave_id << "..." << std::flush;
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::DELETE_MAP, {1,0});
	sock.o_str($start_map);
	ioslaves::answer_code o;
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << LOG_ARROW_OK << "Done !" << std::flush;
}

/** ---------------------------- START ---------------------------- **/

void MServStart () {
	__log__ << LOG_ARROW << "Starting server..." << std::flush;
	int r;
	bool autoselect_slave = false;
	std::vector<std::string> excluded_slaves;
	socketxx::io::simple_socket<socketxx::base_socket>* sock;
	goto _try_start;
_retry_start:
	if (not $granmaster) throw;
	if (autoselect_slave) {
		__log__ << LOG_ARROW << "Trying another slave..." << std::flush;
		excluded_slaves.push_back($slave_id);
		$slave_id.clear();
		goto _try_start;
	} else {
		__log__ << LOG_AROBASE_ERR << "Try an another slave or let the slave selection do its work" << std::flush;
		throw EXCEPT_ERROR_IGNORE;
	}
_try_start:
	if ($granmaster) {
		std::string running_on_slave = ::getRunningOnSlave($server_name);
		if (autoselect_slave)
			goto _continue_launch;
		if (not running_on_slave.empty()) {
			__log__ << LOG_ARROW_ERR << "Server '" << $server_name << "' is probably running on slave '" << running_on_slave << "'" << std::flush;
			__log__ << "Checking on slave '" << running_on_slave << "' on which server should be running now..." << std::flush;
			bool $status = checkSlaveStatus(running_on_slave);
			if ($status) {
				auto sock = getConnection(running_on_slave, $server_name, minecraft::op_code::SERV_STAT, {2,0});
				if (running_on_slave != ::getRunningOnSlave($server_name)) {
					__log__ << LOG_ARROW << "Well... After report, server is now closed. Launching server..." << std::flush;
					goto _continue_launch;
				}
				$status = sock.i_bool();
				if ($status) sock.o_bool(false);
				verifyMapList(running_on_slave, $server_name, sock);
			}
			if ($status) {
				__log__ << LOG_ARROW_ERR << "Yes, server is already running on slave '" << running_on_slave << "' !" << std::flush;
				EXIT_FAILURE = EXIT_FAILURE_IOSL;
				throw EXCEPT_ERROR_IGNORE;
			} else {
				__log__ << LOG_ARROW_ERR << "Erm... No, server isn't running on slave '" << running_on_slave << "'. Marking as closed." << std::flush;
				::setRunningOnSlave($server_name, "");
				EXIT_FAILURE = EXIT_FAILURE_IOSL;
				throw EXCEPT_ERROR_IGNORE;
			}
		}
	_continue_launch:
		if ($slave_id.empty()) {
			autoselect_slave = true;
			__log__ << LOG_AROBASE << "Looking for a good machine..." << std::flush;
			__log__ << "Needed RAM : " << $needed_ram << "MB | Needed CPU : " << std::setprecision(1) << $needed_cpu << std::flush;
			if ($need_quickly) __log__ << "Quickly please !" << std::flush;
			using namespace iosl_dyn_slaves;
			std::string lastsave_from = ioslaves::infofile_get(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",$start_map,"/lastsave_from" ), true);
			if (!ioslaves::validateSlaveName(lastsave_from)) lastsave_from.clear();
			if (not $forced_file.empty()) lastsave_from.clear();
			if (not lastsave_from.empty())
				 __log__ << "Last slave who ran this map : " << lastsave_from << std::flush;
			try {
			std::vector<slave_info> slaves = iosl_dyn_slaves::select_slaves(
				"minecraft", 
				$needed_ram, $needed_cpu,
				$needed_eff, $needed_cpu, 1,
				$need_quickly,
				{ "dyn-hosting" },
				[&] (const slave_info& info) -> points_t {
					for (const std::string& sl : excluded_slaves) 
						if (info.sl_name == sl) return INT32_MIN;
					if (lastsave_from == info.sl_name) return ($need_quickly ? +300 : +200);
					uint32_t net_upload = info.sl_fixed_indices.at("net_upload");
					#define NET_Frontier 100
					#define NET_FrontierQuickly 1000
					if ($need_quickly and net_upload < NET_FrontierQuickly)
						return INT32_MIN;
					if (not $need_quickly and net_upload < NET_Frontier) 
						return (net_upload - NET_Frontier);
					#define NET_MaxPoints 100
					#define NET_MaxPointsQuickly 150
					#define NET_InvF 61000.f
					#define NET_InvFQuickly 240000.f
					#define NET_LinF 0.0023f
					#define NET_LinFQuickly 0.01f
					#define NET_StepPTs 100
					#define NET_InvShift 508.5f
					#define NET_InvShiftQuickly 1220.f
					bool q = $need_quickly;
					return std::max<points_t>( (q?NET_InvFQuickly:NET_InvF)/(-net_upload-(q?NET_InvShiftQuickly:NET_InvShift)) + NET_StepPTs + (q?NET_LinFQuickly:NET_LinF)*net_upload , (q?NET_MaxPointsQuickly:NET_MaxPoints) );
				}
			);
			{ // Nice html table
				std::ostringstream t;
				t << "<table>" << std::setprecision(2);
				t << "<tr> <th>slave</th> <th>stat</th> <th>∆ram</th> <th>pt.ram</th> <th>q.proc</th> <th>pt.proc</th> <th>pt.eff</th> <th>pt.wait</th> <th>pt.net</th> <th>pt.total</th> </tr>";
				for (slave_info& info : slaves) {
					if (info.sl_status == -4 or info.sl_status == -5) continue;
					t << "<tr>";
					bool is_bye = info.sl_total_points == INT32_MIN;
					t << "<th>" << (is_bye?"<del>":"") << info.sl_name << (is_bye?"</del>":"") << "</th>";
					t << "<td>" << info.sl_status << "</td>";
					if (info.sl_status != 0 and info.sl_status != -1) goto bye;
					t << "<td>" << std::get<0>(info._sl_categs_infos) << "</td>";
					#define SlSelTab_PrintPt(_i_) \
						if (std::get<_i_>(info._sl_categs_infos) == INT32_MIN) { t << "<td>bye</td>"; goto bye; } \
						else t << "<td>" << std::get<_i_>(info._sl_categs_infos) << "</td>";
					SlSelTab_PrintPt(1);
					t << "<td>" << std::get<2>(info._sl_categs_infos) << "</td>";
					SlSelTab_PrintPt(3);
					SlSelTab_PrintPt(4);
					SlSelTab_PrintPt(5);
					SlSelTab_PrintPt(6);
					t << "<td>" << info.sl_total_points << "</td>";
				bye:
					t << "</tr>";
				}
				t << "</table>";
				__log__ << t.str() << std::flush;
			}
			if (slaves.size() == 0 or slaves.front().sl_total_points == INT32_MIN) {
				__log__ << LOG_ARROW_ERR << "Sorry, no slave available... " << std::flush;
				throw EXCEPT_ERROR_IGNORE;
			}
			$slave_id = slaves.front().sl_name;
			__log__ << LOG_AROBASE_OK << "Ok, we choose " << $slave_id << " with " << slaves.front().sl_total_points << " points" << std::flush;
			if (slaves.front().sl_status == -1) {
				try {
					iosl_master::slave_start($slave_id, $master_id);
				} catch (std::exception& e) {
					__log__ << LOG_AROBASE_ERR << "Power up error : " << e.what() << std::flush;
					goto _retry_start;
				}
				uint wait_delay = slaves.front().sl_start_delay;
				__log__ << LOG_AROBASE << "Please wait " << wait_delay << "s for slave starting..." << std::flush;
				::sleep(wait_delay);
			}
			} catch (std::exception& e) {
				__log__ << LOG_AROBASE_ERR << "Error while selecting slave : " << e.what() << std::flush;
				throw EXCEPT_ERROR_IGNORE;
			}
		}
	}
	try {
		sock = new socketxx::io::simple_socket<socketxx::base_socket> (
			getConnection($slave_id, $server_name, minecraft::op_code::START_SERVER, {2,0}, !autoselect_slave)
		);
	} catch (OPTCTX_POSTFNCT_EXCEPT_T) {
		goto _retry_start;
	}
	__log__ << "Sending infos..." << std::flush;
	sock->o_char((char)$start_serv_type);
	sock->o_str($start_jar_ver);
	sock->o_int<uint16_t>($needed_ram);
	sock->o_bool($start_is_perm);
	__log__ << " - " << ($start_is_perm?"permanent":"temporary") << " map : " << $start_map << std::flush;
	if ($autoclose_time == (time_t)-1) $autoclose_time = $needed_time;
	if ($autoclose_time != 0) 
		__log__ << " - autoclose time : " << $autoclose_time/60 << "min" << std::flush;
	sock->o_int<uint32_t>((uint32_t)$autoclose_time);
	__log__ << " - view distance : " << (int)$mc_viewdist << std::flush;
	sock->o_int<uint8_t>($mc_viewdist);
	__log__ << " - time estimation : " << $needed_time/60 << "min" << std::flush;
	sock->o_int<uint32_t>((uint32_t)$needed_time);
	sock->o_str($start_map);
	time_t lastsavetime;
	if (not $forced_file.empty()) {
		lastsavetime = -1;
	} else {
		if ($granmaster and $start_is_perm) lastsavetime = getLastSaveTime($server_name, $start_map);
		else lastsavetime = 0;
	}
	__log__ << " - last-save-time : " << lastsavetime << std::flush;
	sock->o_int<int64_t>(lastsavetime);
	sock->o_bool($start_earlyconsole);
	ioslaves::answer_code o;
	if ((o = (ioslaves::answer_code)sock->i_char()) != ioslaves::answer_code::OK) {
		if (o == ioslaves::answer_code::BAD_STATE and $granmaster) {
			__log__ << NICE_WARNING << COLOR_YELLOW << "Server is already opened on distant slave" << COLOR_RESET << " - marking as opened" << std::flush;
			::setRunningOnSlave($server_name, $slave_id);
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		} else if (o == ioslaves::answer_code::LACK_RSRC) {
			__log__ << LOG_AROBASE_ERR << "Lacking ressources on slave '" << $slave_id << "' : can't start server !" << std::flush;
			goto _retry_start;
		} else
			throw o;
	}
	in_port_t port = sock->i_int<uint16_t>();
	__log__ << LOG_AROBASE << "Waiting queries or ack from minecraft service" << std::flush;
	while ((o = (ioslaves::answer_code)sock->i_char()) != ioslaves::answer_code::OK) {
		if (o == ioslaves::answer_code::EXISTS and not $start_is_perm) {
			__log__ << LOG_ARROW_ERR << "A permanent map named '" << $start_map << "' already exists on slave " << NICE_WARNING << " Delete it if wanted." << std::flush;
			if (not $granmaster) throw o;
			__log__ << LOG_AROBASE << "Refreshing status..." << std::flush;
			auto sock = getConnection($slave_id, $server_name, minecraft::op_code::SERV_STAT, {1,0});
			bool stat = sock.i_bool();
			if (stat) sock.o_bool(false);
			verifyMapList($slave_id, $server_name, sock);
			throw o;
		}
		if (o == ioslaves::answer_code::WANT_GET) {
			minecraft::transferWhat what = (minecraft::transferWhat)sock->i_char();
			if (not $forced_file.empty() and (what == minecraft::transferWhat::SERVFOLD or what == minecraft::transferWhat::MAP)) {
				__log__ << LOG_AROBASE << " Want get map : sending forced file" << std::flush;
				sock->o_bool(true);
				sock->o_file($forced_file.c_str());
			} 
			else if ($granmaster and what == minecraft::transferWhat::JAR) {
				__log__ << LOG_AROBASE << " Want get jar" << std::flush;
				bool vanilla = sock->i_bool();
				std::string jar_ver = $start_jar_ver;
				if (vanilla) { jar_ver = ioslaves::version(jar_ver, true).strdigits(); }
				const char* jar_prefix;
					  if ($start_serv_type == minecraft::serv_type::VANILLA or vanilla) jar_prefix = "mc_vanilla_";
				else if ($start_serv_type == minecraft::serv_type::BUKKIT) jar_prefix = "mc_bukkit_";
				else if ($start_serv_type == minecraft::serv_type::FORGE) jar_prefix = "mc_forge_";
				else if ($start_serv_type == minecraft::serv_type::CAULDRON) jar_prefix = "mc_cauldron_";
				else if ($start_serv_type == minecraft::serv_type::SPIGOT) jar_prefix = "mc_spigot_";
				else { sock->o_bool(false); continue; }
				std::string jar_name, jar_path = _s( IOSLAVES_MINECRAFT_MASTER_JAR_DIR,'/',(jar_name=_s(jar_prefix,jar_ver,".jar")) );
				r = ::access(jar_path.c_str(), R_OK);
				if (r == -1) {
					sock->o_bool(false);
					__log__ << LOG_ARROW_ERR << "Minecraft jar '" << jar_name << "' not found for sending to slave" << std::flush;
					EXIT_FAILURE = EXIT_FAILURE_IOSL;
					throw EXCEPT_ERROR_IGNORE;
				}
				sock->o_bool(true);
				sock->o_file(jar_path.c_str());
			} else if ($granmaster and what == minecraft::transferWhat::BIGFILE) {
				std::string bigfile_name = sock->i_str();
				__log__ << LOG_AROBASE << " Want get bigfile named '" << bigfile_name << "'" << std::flush;
				std::string bigfile_path = _S( IOSLAVES_MINECRAFT_MASTER_BIGFILES_DIR,'/',bigfile_name );
				struct stat fst;
				int r = ::stat(bigfile_path.c_str(), &fst);
				if (r == 0 and (fst.st_mode & S_IFMT) != S_IFREG) { r = -1; errno = EISDIR; }
				if (r == -1) {
					sock->o_bool(false);
					__log__ << LOG_AROBASE_ERR << "Can't send bigfile '" << bigfile_name << "' to slave : " << ::strerror(errno) << std::flush;
					EXIT_FAILURE = EXIT_FAILURE_IOSL;
					throw EXCEPT_ERROR_IGNORE;
				}
				sock->o_bool(true);
				sock->o_file(bigfile_path.c_str());
			} else if ($granmaster) {
				__log__ << LOG_AROBASE << " Want get map (" << (char)what << ") : ";
				if (not $start_is_perm) {
					__log__ << "sending temporary map " << $start_map << std::flush;
					if (what != minecraft::transferWhat::MAP) { sock->o_bool(false); continue; }
					std::string tempmap_path = _S( IOSLAVES_MINECRAFT_MASTER_TEMPAMP_DIR,'/',$start_map,".zip" );
					r = ::access(tempmap_path.c_str() , R_OK);
					sock->o_bool(r == 0);
					if (r == -1) {
						__log__ << LOG_ARROW_ERR << "Temporary map '" << $start_map << "' doesn't exist here" << std::flush;
						EXIT_FAILURE = EXIT_FAILURE_IOSL;
						throw EXCEPT_ERROR_IGNORE;
					}
					sock->o_file(tempmap_path.c_str());
				} else {
					std::string mapfold = _S( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/maps/",$start_map );
					if (what != minecraft::transferWhat::SERVFOLD) {
						__log__ << NICE_WARNING << "master wants other than a perm save !" << std::flush;
						sock->o_bool(false);
						continue;
					}
					if (lastsavetime == 0) {
						__log__ << NICE_WARNING << "no save for map " << $start_map << " available !" << std::flush;
						sock->o_bool(false);
						continue;
					}
					if (ioslaves::infofile_get( _s(mapfold,"/truesave"), true) != "true") {
						__log__ << NICE_WARNING << "local save " << $start_map << " could be not the last save !" << std::flush;
						sock->o_bool(false);
						continue;
					}
					__log__ << "sending server folder save " << $start_map << std::flush;
					sock->o_bool(true);
					std::string map_path = _S( mapfold,'/',$start_map,'_',::ixtoa(lastsavetime,IX_HEX_MAJ),".zip" );
					sock->o_file(map_path.c_str());
				}
			} else {
				sock->o_bool(false);
				throw o;
			}
		} else if (o == ioslaves::answer_code::WANT_SEND) {
			if ($granmaster) 
				acceptFileSave(*sock, $server_name, $start_map, $slave_id);
			else {
				sock->i_int<int64_t>();
				sock->o_bool(false);
				__log__ << LOG_AROBASE_ERR << "Not granmaster : ignoring send request" << std::flush;
			}
		} else 
			throw o;
	}
	if ($start_is_perm and $granmaster) {
		std::string map_folder = _S( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/maps/",$start_map );
		r = ::mkdir(map_folder.c_str(), S_IRWXU|S_IRWXG);
		if (r == -1 and errno != EEXIST) {
			__log__ << LOG_AROBASE_ERR << "Can't create map folder '" << $start_map << "' : " << ::strerror(errno) << std::flush;
			throw EXCEPT_ERROR_IGNORE;
		}
		ioslaves::infofile_set(_s(IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/maps/",$start_map,"/truesave"), "false");
	}
	__log__ << LOG_AROBASE_OK << "End of requests, starting of server on port " << port << " can now start..." << std::flush;
	if ((o = (ioslaves::answer_code)sock->i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << "Server thread is started" << std::flush;
	if ((o = (ioslaves::answer_code)sock->i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << "Java process is alive" << std::flush;
	if ($start_earlyconsole) {
		if ($granmaster) 
			::setRunningOnSlave($server_name, $slave_id);
		__log__ << LOG_ARROW << "Starting early LiveConsole on port " << $websocket_port << " via minecraft-master..." << std::flush;
		ioslaves::fork_exec("minecraft-master", {$master_id, $slave_id, "-i", "--websocket", ::ixtoa($websocket_port) ,"--server", $server_name, "--console"}, 
								  false, NULL, true, -1, -1, true);
		__log__ << LOG_AROBASE_OK << "Exiting." << std::flush;
	} else {
		if ((o = (ioslaves::answer_code)sock->i_char()) != ioslaves::answer_code::OK) 
			throw o;
		__log__ << LOG_ARROW_OK << "Done ! Server is started" << std::flush;
		if ($granmaster) 
			::setRunningOnSlave($server_name, $slave_id);
	}
}

/** ---------------------------- STOP ---------------------------- **/

void MServStop () {
	__log__ << LOG_ARROW << "Stopping server..." << std::flush;
	if ($granmaster) {
		std::string running_on_slave = ::getRunningOnSlave($server_name);
		if (running_on_slave.empty()) {
			__log__ << LOG_ARROW_ERR << "Server '" << $server_name << "' is (probably) not running !" << std::flush;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		}
		$slave_id = running_on_slave;
	}
	ioslaves::answer_code o;
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::STOP_SERVER, {2,0});
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) {
		if (o == ioslaves::answer_code::NOT_FOUND and $granmaster) {
			__log__ << NICE_WARNING << COLOR_RED << "Server is not running on slave '" << $slave_id << "'" << COLOR_RESET << std::flush;
			::setRunningOnSlave($server_name, "");
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		} else 
			throw o;
	}
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << LOG_ARROW_OK << "Server is stopping..." << std::flush;
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << LOG_ARROW_OK << "Thread and java exited" << std::flush;
	while ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) {
		if (o == ioslaves::answer_code::WANT_REPORT)
			handleReportRequest(sock, $slave_id);
		else throw o;
	}
	if ($granmaster) 
		::setRunningOnSlave($server_name, "");
	__log__ << LOG_ARROW_OK << "Done ! Server is stopped" << std::flush;
}

/** ---------------------------- CONSOLE ---------------------------- **/

void MServConsole () {
	__log__ << LOG_ARROW << "Connecting to LiveConsole™..." << std::flush;
	if ($locked) {
		::unlink(_s( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/_mcmaster.lock" ));
		$locked = false;
	}
	if ($granmaster) {
		std::string running_on_slave = ::getRunningOnSlave($server_name);
		if (running_on_slave.empty()) {
			__log__ << LOG_ARROW_ERR << "Server '" << $server_name << "' is (probably) not running !" << std::flush;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		}
		$slave_id = running_on_slave;
	}
	ioslaves::answer_code o;
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::COMM_SERVER, {6,0});
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << "Connected to thread" << std::flush;
	sock.o_char((char)minecraft::serv_op_code::LIVE_CONSOLE);
	sock.o_bool($websocket_port==0);
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << "Connection between master and thread is now established for LiveConsole !" << ($websocket_port==0?"":" [accepting commands]") << std::flush;
	if ($websocket_port == 0) {
		while (true) {
			time_t line_time = (time_t)sock.i_int<int64_t>();
			if (line_time == -1) {
				__log__ << LOG_ARROW << "LiveConsole : server thread hanged up" << std::flush;
				return;
			}
			std::string line_msg = sock.i_str();
			tm gmt_time;
			::gmtime_r(&line_time, &gmt_time);
			char time_str[30];
			::strftime(time_str, 30, "%F %TZ ", &gmt_time);
			__log__ << time_str << line_msg << std::flush;
		}
	} else try {
		int r;
		fd_set select_set;
		FD_ZERO(&select_set);
		FD_SET(sock.get_fd(), &select_set);
		fd_t websock = nopoll_conn_socket($websocket_conn);
		FD_SET(websock, &select_set);
		fd_t select_max = (websock > sock.get_fd()) ? websock+1 : sock.get_fd()+1;
		while (true) {
			fd_set sel_set = select_set;
			errno = 0;
			r = ::select(select_max, &sel_set, NULL, NULL, NULL);
			if (r != 1 and r != 2) {
				if (errno != EINTR)
					throw xif::sys_error("LiveConsole pool : select() error");
			} else {
				if (FD_ISSET(sock.get_fd(), &sel_set)) {
					int64_t line_time = sock.i_int<int64_t>();
					if (line_time == -1) {
						__log__ << LOG_ARROW << "LiveConsole : server thread hanged up" << std::flush;
						nopoll_conn_close($websocket_conn);
						$websocket_conn = NULL;
						return;
					}
					std::string line_msg = sock.i_str();
					std::string weblog_html = _S( "<log_serv time=\"",::ixtoa(line_time),"\">",line_msg,"</log_serv>" );
					int rs = nopoll_conn_send_text($websocket_conn, weblog_html.c_str(), weblog_html.length());
					if (rs != (int)weblog_html.length()) 
						throw std::runtime_error("Error while writing to websocket client");
				}
				if (FD_ISSET(websock, &sel_set)) {
					noPollMsg* msg = nopoll_conn_get_msg($websocket_conn);
					if (msg != NULL) {
						std::string command ((const char*)nopoll_msg_get_payload(msg), nopoll_msg_get_payload_size(msg));
						nopoll_msg_unref(msg);
						sock.o_str(command);
						if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
							throw o;
						continue;
					} else {
						nopoll_conn_close($websocket_conn);
						$websocket_conn = NULL;
						__log__ << LOG_ARROW << "LiveConsole : websocket client hanged up" << std::flush;
						return;
					}
				}
			}
		}
	} catch (std::exception& e) {
		nopoll_conn_close($websocket_conn);
		$websocket_conn = NULL;
		__log__ << LOG_ARROW_ERR << "LiveConsole pool : end by error" << std::flush;
		EXIT_FAILURE = EXIT_FAILURE_COMM;
		throw EXCEPT_ERROR_IGNORE;
	}
}

void MServCreate () {
	__log__ << LOG_ARROW << "Creating server folder and state conf file..." << std::flush;
	int r;
	r = ::mkdir( _s(IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name), S_IRWXU|S_IRWXG);
	if (r == -1)
		throw xif::sys_error("failed to create client dir");
	r = ::mkdir( _s(IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/maps"), S_IRWXU|S_IRWXG);
	if (r == -1) 
		throw xif::sys_error("failed to create maps dir");
	::setRunningOnSlave($server_name, "");
}

void MPost (ioslaves::answer_code e) {
	if (e == EXCEPT_ERROR_IGNORE) throw EXCEPT_ERROR_IGNORE;
	if (e != ctx_postfnct_excpt_default) {
		switch (e) {
			case ioslaves::answer_code::OK: __log__ << COLOR_GREEN << "Success !" << COLOR_RESET << std::flush; return;
			case ioslaves::answer_code::MAY_HAVE_FAIL: __log__ << COLOR_YELLOW << "Opperation may have fail !" << COLOR_RESET << std::flush; return;
			default: goto __error;
		}
	__error:
		const char* errstr = NULL;
		switch (e) {
			case ioslaves::answer_code::INTERNAL_ERROR: errstr = "Slave system or internal error !"; break;
			case ioslaves::answer_code::SECURITY_ERROR: errstr = "Security error !"; break;
			case ioslaves::answer_code::NOT_FOUND: errstr = "Not Found !"; break;
			case ioslaves::answer_code::BAD_STATE: errstr = "Opperation inapplicable : bad state !"; break;
			case ioslaves::answer_code::BAD_TYPE: errstr = "Opperation inapplicable : bad type !"; break;
			case ioslaves::answer_code::WANT_REPORT: errstr = "Slave want to report something : can't handle request"; break;
			case ioslaves::answer_code::WANT_GET: errstr = "Slave want to get something : can't handle request"; break;
			case ioslaves::answer_code::WANT_SEND: errstr = "Slave want to tranfer something : can't handle request"; break;
			case ioslaves::answer_code::OP_NOT_DEF: errstr = "Opperation not defined !"; break;
			case ioslaves::answer_code::EXISTS: errstr = "Already exists !"; break;
			case ioslaves::answer_code::UPNP_ERROR: errstr = "Port mapping error !"; break;
			case ioslaves::answer_code::DENY: errstr = "Slave refuses !"; break;
			case ioslaves::answer_code::INVALID_DATA: errstr = "Slave reports invalid data !"; break;
			case ioslaves::answer_code::LACK_RSRC: errstr = "Lacking ressources !"; break;
			case ioslaves::answer_code::EXTERNAL_ERROR: errstr = "Error outside the scope of ioslavesd-minecraft !"; break;
			default: case ioslaves::answer_code::ERROR: errstr = "Unknown error !";
		}
		__log__ << COLOR_RED << errstr << COLOR_RESET << std::flush;
		EXIT_FAILURE = EXIT_FAILURE_IOSL;
		throw EXCEPT_ERROR_IGNORE;
	}
}
