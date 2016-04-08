/**********************************************************\
 *          ioslaves : ioslaves master : Minecraft
 *   Master program for controlling Minecraft API service
 * *********************************************************
 * Copyright © Félix Faisant 2013-2016. All rights reserved
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
#include <math.h>
#include <xifutils/cxx.hpp>
#include <xifutils/intstr.hpp>

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

	// Timeouts
#define TIMEOUT_CONNECT timeval{2,500000}
#define TIMEOUT_COMM timeval{10,000000}
#define TIMEOUT_ZIP_DELAY timeval{130,000000}
#define TIMEOUT_JAVA_ALIVE timeval{60,000000}
#define TIMEOUT_STOP_SERVER timeval{30,000000}
#define TIMEOUT_WEBSOCKET (useconds_t)4000000

	// minecraft-master option variables
bool $granmaster;
std::string $master_id;
std::string $slave_id;
bool $refuse_servs;
std::string $server_name;
minecraft::serv_type $start_serv_type;
std::string $start_jar_ver;
bool $start_is_perm;
std::string $worldname;
bool $start_earlyconsole = false;
std::string $forced_file;
bool $verify_serv_exists = true;
bool $locked = false;
in_port_t $websocket_port = 0;
noPollConn* $websocket_conn = NULL;
bool $refuse_save = false;
iosl_dyn_slaves::ram_megs_t $needed_ram = 1024;
iosl_dyn_slaves::proc_power_t $needed_cpu = 1.0f;
iosl_dyn_slaves::proc_power_t $mean_cpu = 0.f;
float $threads_num = 1.f;
iosl_dyn_slaves::efficiency_ratio_t $needed_eff = iosl_dyn_slaves::efficiency_ratio_t::REGARDLESS;
bool $hint = false;
time_t $needed_time = 0;
std::string $ftp_user, $ftp_hash_passwd;
uint8_t $mc_viewdist = 7;
time_t $autoclose_time = 0;
in_port_t $port = 0;
std::vector<in_port_t> $additional_ports;
bool $start_temp_perm = false;
bool $fixmap;

	// minecraft-master core functionnality functions
time_t getLastSaveTime (std::string serv, std::string map);
void retreivingProgressionShow (size_t done, size_t totsz);
void handleReportRequest (socketxx::io::simple_socket<socketxx::base_socket> sock, std::string slave);
void acceptFileSave (socketxx::io::simple_socket<socketxx::base_socket> sock, std::string servname, std::string mapname, std::string slave, bool truesave);
std::string getRunningOnSlave (std::string server);
void setRunningOnSlave (std::string server, std::string running_on_slave);
void verifyMapList (std::string slave_id, std::string server_name, socketxx::io::simple_socket<socketxx::base_socket> sock);
socketxx::io::simple_socket<socketxx::base_socket> getConnection (std::string slave, std::string servname, minecraft::op_code opp, timeval timeout, bool autostart = false, bool autoservice = true);
	void MServPre ();
		void MServStart ();
		void MServStop ();
		void MServStatus ();
		void MServPerm ();
		void MServDelMap ();
		void MServFixMap ();
		void MServSaveMap ();
		void MServCreate ();
		void MServConsole ();
		void MServFTPSess ();
		void MServKill();
	void MServPost(ioslaves::answer_code);
	void MRefuse();
void MPost (ioslaves::answer_code);

	// Commmand line arguments
#define OPTCTX_IMPL

#define OPTCTX_POSTFNCT_EXCEPT_T ioslaves::answer_code
#define OPTCTX_POSTFNCT_EXCEPT_DEFAULT (ioslaves::answer_code)0

#define OPTCTX_CTXS                              refuseServs     , mcserv                   , servStart        , servStop        , servCreate        , servStatus        , servPerm        , servConsole        , servDelMap        , servFixMap        , servSaveMap        , servFTPSess        , servKill
#define OPTCTX_PARENTS                           ROOT            , ROOT                     , mcserv           , mcserv          , mcserv            , mcserv            , mcserv          , mcserv             , mcserv            , mcserv            , mcserv             , mcserv             , mcserv
#define OPTCTX_PARENTS_NAMES  "action"         , NULL            , "server action"          , NULL             , NULL            , NULL              , NULL              , NULL            , NULL               , NULL              , NULL              , NULL               , NULL               , NULL
#define OPTCTX_PARENTS_FNCTS  CTXFP(NULL,MPost), CTXFO(MRefuse)  , CTXFP(MServPre,MServPost), CTXFO(MServStart), CTXFO(MServStop), CTXFO(MServCreate), CTXFO(MServStatus), CTXFO(MServPerm), CTXFO(MServConsole), CTXFO(MServDelMap), CTXFO(MServFixMap), CTXFO(MServSaveMap), CTXFO(MServFTPSess), CTXFO(MServKill)
#define OPTCTX_NAMES                             "--refuse-servs", "--server"               , "--start"        , "--stop"        , "--create"        , "--status"        , "--permanentize", "--console"        , "--del-world"     , "--fix-world"     , "--save-world"     , "--ftp-sess"       , "--kill"

#define OPTCTX_PROG_NAME "minecraft-master"
#include <xifutils/optctx.hpp>

inline void tryParseMasterID (int argc, char* const argv[]) {
	if (not $master_id.empty()) return;
	if (argc == optind || argv[optind][0] == '-') 
		return;
	$master_id = argv[optind++];
	if (!ioslaves::validateMasterID($master_id)) 
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

#define IOSLAVES_LOG_DEFAULT_LOGSTREAM_IMPL
#include "log_defimpl.h"
pthread_mutex_t xlog::logstream_impl::mutex = PTHREAD_MUTEX_INITIALIZER;
std::ostringstream xlog::logstream_impl::stream;
bool _log_wait_flag = false;
void xlog::logstream_impl::log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid) noexcept {
	if (_log_wait_flag and not (m & LOG_ADD)) ::__log__ << std::flush;
	_log_wait_flag = false;
	switch (lvl) {
		case log_lvl::LOG: case log_lvl::_DEBUG: break;
		case log_lvl::NOTICE: case log_lvl::IMPORTANT: case log_lvl::MAJOR: ::__log__<< LOG_ARROW; break;
		case log_lvl::FATAL: case log_lvl::ERROR: case log_lvl::OOPS: case log_lvl::SEVERE: ::__log__ << LOG_ARROW_ERR << COLOR_RED << "Error : " << COLOR_RESET; break;
		case log_lvl::WARNING: ::__log__ << COLOR_YELLOW << "Warning : " << COLOR_RESET; break;
		case log_lvl::DONE: ::__log__ << LOG_ARROW_OK; break;
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
				{"bungeecord", required_argument, NULL, (char)minecraft::serv_type::BUNGEECORD},
				{"temp-map", required_argument, NULL, 'm'},
				{"perm-world", required_argument, NULL, 'p'},
				{"map-file", required_argument, NULL, 'z'},
				{"ram", required_argument, NULL, 'a'},
				{"cpu", required_argument, NULL, 'u'},
				{"duration", required_argument, NULL, 'd'},
				{"autoclose", required_argument, NULL, 'j'},
				{"viewdist", required_argument, NULL, 'e'},
				{"threads", required_argument, NULL, '#'},
				{"mean-cpu", required_argument, NULL, '~'},
				{"port", required_argument, NULL, '>'},
				{"additional-ports", required_argument, NULL, '+'},
				{"hint", no_argument, NULL, '`'},
			{"stop", no_argument, NULL, 'o'},
			{"kill", no_argument, NULL, 'k'},
			{"status", no_argument, NULL, 't'},
			{"permanentize", no_argument, NULL, 'P'},
			{"del-world", required_argument, NULL, 'D'},
			{"fix-world", required_argument, NULL, '-'},
			{"save-world", required_argument, NULL, 'v'},
			{"console", no_argument, NULL, 'l'},
			{"ftp-sess", required_argument, NULL, 'f'},
			{"create", no_argument, NULL, 'c'},
		{"refuse-servs", required_argument, NULL, 'x'},
		{NULL, 0, NULL, 0}
	};
	
	int opt, opt_charind = 0;
	while ((opt = ::getopt_long(argc, argv, "-hiGw:r", long_options, &opt_charind)) != -1) {
		switch (opt) {
			case 'h':
				::puts("minecraft-master | ioslaves-master warper program for controling Minecraft service\n"
				       "Usage: minecraft-master MASTER-ID (--granmaster [SLAVE-ID])|(SLAVE-ID) (--server=NAME) --ACTION\n"
				       "\n"
				       "General options :\n"
				       "  -i, --no-interactive     Enbale HTML log and JSON outputs\n"
				       "  -G, --granmaster         The real and principal purpose of minecraft-master : manage automagically\n"
					   "                            slaves, servers and worlds : world saves, status tracking, fixed mode...\n"
					   "                            Here minecraft-master supposes that it is the unique granmaster-mode master.\n"
				       "  -w, --websocket=PORT     Wait a websocket client on PORT before executing commands and\n"
				       "                            output log via this websocket client. Used also for live-console\n"
				       "  -r, --refuse-save        Refuse incoming requests to save a world folder.\n"
				       "\n"
				       "  --server=NAME               Control the Minecraft server named [NAME]. Mandatory.\n"
				       "      Server Actions :\n"
				       "        --start PARAMS          Start the server. Jar and map parameters are requiered\n"
				       "                                and must be each unique.\n"
				       "            Start Parameters :\n"
				       "              --[bukkit|vanilla|forge|spigot|cauldron|bungeecord]=VER | --customjar=NAME\n"
				       "                                  Launch Minecraft with this .jar\n"
				       "                                  Custom jar must be in server folder\n"
				       "              --temp-map=NAME | --perm-world=NAME\n"
				       "                                  Launch temporary map (the server folder will be deleted\n"
				       "                                   at stop) or permanent world (folder will be updated on\n"
				       "                                   server/granmaster if older/newer than master's one).\n"
				       "                  --map-file=PATH   Use zip archive to send temp map or to to overwrite world folder\n"
				       "                                     on the slave, for example to start server with an old save of\n"
				       "                                     the world. Zipped dir must have the same name than the world.\n"
				       "                  --permanentize    Prevent the current temp map from being deleted at server stop.\n"
				       "              --duration=TIME     Server running duration, in seconds. Must be a good estimation.\n"
				       "            Slave selection :\n"
				       "              --cpu=CPU           Needed CPU, using CPU unit (1.0 = Core2Duo E4400).\n"
				       "              --ram=MEGS          Needed memory, in megabytes.\n"
				       "            Optional :\n"
				       "              --mean-cpu=CPU      Mean CPU power use estimation (≠ max needed CPU).\n"
				       "              --threads=NUMBER    Non-integer number of threads which can be used by this jar.\n"
				       "              --autoclose=TIME    Server will close after TIME sec. without players.\n"
				       "                                   Default = 0 = disabled\n"
				       "              --viewdist=CHUNKS   Minecraft view distance. Default = 7\n"
					   "              --port=MC_TCP_PORT  Choice of Minecraft TCP listening port is no more left to slave.\n"
				       "              --additional-ports=P1,P2…  Open additional TCP ports (for JSONAPI for exemple).\n"
				       "                                   Should be attributed uniquely across the network.\n"
				       "              --hint              Take [SALVE-ID] only as a hint for slave selection.\n"
				       "        --stop                  Stop the server.\n"
				       "        --kill                  Kill a buggy server (may corrupt map; no stop report).\n"
				       "        --status                Refresh status of the server and updates local status.\n"
				       "        --permanentize          Mark current world as permanent (will not be deleted at server stop).\n"
				       "        --del-world=NAME        Delete the folder of the world [NAME] of the server.\n"
				       "        --fix-world=(y|n),NAME  Guarantee that the world [NAME] will stay on the indicated slave.\n"
				       "        --save-world=NAME       Force world save retrieval of the world [NAME] of the server.\n"
				       "        --console               Bind the connection to the server LiveConsole. If used at\n"
				       "                                 after server start action, early LiveConsole is activated.\n"
				       "        --ftp-sess=USER:HASHPW  Create new FTP session for running world for user USER and\n"
				       "                                 hashed password HASHPW. Returns ADDR:PORT of the FTP server.\n"
				       "        --create                Create a new server in database.\n"
				       "\n"
				       "Other actions (slave-id mandatory) :\n"
				       "  --refuse-servs=[y|n]        Make the slave accepting or refusing server start requests.\n"
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
					// Create ioslaves-master and minecraft-master dirs if not exist
				r = ::access(IOSLAVES_MASTER_DIR, F_OK);
				if (r == -1) {
					r = ::mkdir(IOSLAVES_MASTER_DIR, 0740);
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
							std::cerr << COLOR_RED << "Can't create minecraft-master directory" << COLOR_RESET << " (" << IOSLAVES_MINECRAFT_MASTER_DIR << ") : " << ::strerror(errno) << std::endl;
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
					try_help("not in granmaster mode : slave ID must be defined");
				optctx::optctx_set(optctx::mcserv);
				$server_name = optarg;
				if (!ioslaves::validateServiceName($server_name))
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
			case (char)minecraft::serv_type::BUNGEECORD:
			{	const char* servtype = NULL;
				for (size_t i = 0; long_options[i].name != NULL; i++) 
					if (long_options[i].val == opt) 
						servtype = long_options[i].name;
				optctx::optctx_test(servtype, optctx::servStart);
				$start_serv_type = (minecraft::serv_type)opt;
				$start_jar_ver = optarg;
				try {
					ioslaves::version($start_jar_ver, true);
				} catch (const std::exception& e) { try_help(_s("jar: invalid version str : ",e.what(),"\n")); }
			} break;
			case 'm':
				optctx::optctx_test("--temp-map", optctx::servStart);
				$start_is_perm = false;
				$worldname = optarg;
				if (!ioslaves::validateName($worldname))
					try_help("--temp-map: invalid map name\n");
				break;
			case 'p':
				optctx::optctx_test("--perm-world", optctx::servStart);
				$start_is_perm = true;
				$worldname = optarg;
				if (!ioslaves::validateName($worldname))
					try_help("--perm-world: invalid world name\n");
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
				if (f == 0.0 or f <= 0.0 or f > 50.0)
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
				if ($needed_time < 3600*2) $needed_eff = iosl_dyn_slaves::efficiency_ratio_t::FOR_HOURS_MEDIUM;
				else {
					if ($needed_time < 3600*16) $needed_eff = iosl_dyn_slaves::efficiency_ratio_t::FOR_DAY_HIGH;
					else $needed_eff = iosl_dyn_slaves::efficiency_ratio_t::FOR_DAYS_HIGHEST;
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
			case '>':
				optctx::optctx_test("--port", optctx::servStart);
				try {
					$port = ::atoix<in_port_t>(optarg);
				} catch (const std::exception& e) {
					try_help(_s("--port : invalid port : ",e.what(),"\n"));
				}
				break;
			case '+': 
				optctx::optctx_test("--additional-ports", optctx::servStart);
				try {
					std::string arg = optarg;
					size_t start = 0, end = 0;
					while ((end = arg.find(',', start)) != std::string::npos) {
						std::string portstr = arg.substr(start, end-start);
						start = end + 1;
						in_port_t port = ::atoix<in_port_t>(portstr);
						$additional_ports.push_back(port);
					}
					in_port_t port = ::atoix<in_port_t>( arg.substr(start) );
					$additional_ports.push_back(port);
				} catch (const std::exception& e) {
					try_help(_s("--additional-ports : invalid port list : ",e.what(),"\n"));
				}
				break;
			case '`':
				optctx::optctx_test("--hint", optctx::servStart);
				$hint = true;
				break;
			case 'j':
				optctx::optctx_test("--autoclose", optctx::servStart);
				try {
					$autoclose_time = ::atoix<uint32_t>(optarg);
				} catch (...) {
					try_help("--autoclose : invalid time\n");
				}
				break;
			case '~': {
				optctx::optctx_test("--mean-cpu", optctx::servStart);
				double f = ::atof(optarg);
				if (f == 0.0 or f <= 0.0 or f > 20.0 or $mean_cpu > $needed_cpu)
					try_help("--mean-cpu : invalid mean cpu usage estimation\n");
				$mean_cpu = (float)f;
			} break;
			case '#': {
				optctx::optctx_test("--threads", optctx::servStart);
				double f = ::atof(optarg);
				if (f < 0.99)
					try_help("--threads : invalid usable thread number\n");
				$threads_num = (float)f;
			} break;
			case 'o':
				optctx::optctx_set(optctx::servStop);
				break;
			case 'k':
				optctx::optctx_set(optctx::servKill);
				break;
			case 't':
				optctx::optctx_set(optctx::servStatus);
				break;
			case 'P':
				if (optctx::optctx == optctx::servStart and $start_is_perm == false) {
					$start_temp_perm = true;
					break;
				}
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
				$worldname = optarg;
				if (!ioslaves::validateName($worldname))
					try_help("--del-world: invalid world name\n");
				break;
			case 'v':
				optctx::optctx_set(optctx::servSaveMap);
				$worldname = optarg;
				if (!ioslaves::validateName($worldname))
					try_help("--save-world: invalid world name\n");
				break;
			case '-': {
				if (not $granmaster) 
					try_help("--fix-world : meaningful only in granmaster mode");
				optctx::optctx_set(optctx::servFixMap);
				std::string arg = _S( optarg );
				if (arg.substr(0,2) == "y,") 
					$fixmap = true;
				else if (arg.substr(0,2) == "n,") 
					$fixmap = false;
				else 
					try_help("--fix-world: 'y,[WORLD]' or 'n,[WORLD]'\n");
				$worldname = arg.substr(2, std::string::npos);
				if (!ioslaves::validateName($worldname))
					try_help("--fix-world: invalid world name\n");
			} break;
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
			case 'x':
				optctx::optctx_set(optctx::refuseServs);
				if (_S("y") == optarg) 
					$refuse_servs = true;
				else if (_S("n") == optarg) 
					$refuse_servs = false;
				else 
					try_help("--refuse-servs: 'y' or 'n'\n");
				if ($slave_id.empty()) 
					try_help("--refuse-servs: slave-id must be defined\n");
				break;
			default: 
				try_help();
		}
	}
	optctx::optctx_end();
	if (optctx::optctx == optctx::servStart) {
		if ($worldname.empty()) 
			try_help("--start : a world parameter (--perm-world or --temp-map) must be defined\n");
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
				EXIT_FAILURE = EXIT_FAILURE_EXTERR;
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
			std::cerr << LOG_AROBASE_ERR << "Failed to create websocket context" << std::endl; EXIT_FAILURE = EXIT_FAILURE_SYSERR; return EXIT_FAILURE; }
		noPollConn* listener = nopoll_listener_new(wsctx, "0.0.0.0", ::ixtoa($websocket_port).c_str());
		if (not nopoll_conn_is_ok(listener)) {
			std::cerr << LOG_AROBASE_ERR << "Failed to create listening websocket" << std::endl; EXIT_FAILURE = EXIT_FAILURE_SYSERR; return EXIT_FAILURE; }
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
			nopoll_loop_wait(wsctx, TIMEOUT_WEBSOCKET);
		} catch (const std::exception) {}
		nopoll_conn_close(listener);
		if ($websocket_conn == NULL) {
			std::cerr << LOG_AROBASE_ERR << "Can't get websocket client..." << std::endl;
			EXIT_FAILURE = EXIT_FAILURE_EXTERR;
			return EXIT_FAILURE;
		}
	}
	
		// Execute
	try {
		optctx::optctx_exec();
	} catch (const OPTCTX_POSTFNCT_EXCEPT_T) {
		return EXIT_FAILURE;
	} catch (const xif::sys_error& se) {
		__log__ << NICE_WARNING << COLOR_RED << "System error" << COLOR_RESET << " : " << se.what() << std::flush;
		return EXIT_FAILURE;
	} catch (const socketxx::error& ne) {
		__log__ << NICE_WARNING << COLOR_RED << "Network error" << COLOR_RESET << " : " << ne.what() << std::flush;
		return EXIT_FAILURE;
	} catch (const std::runtime_error& re) {
		__log__ << NICE_WARNING << COLOR_RED << "Error" << COLOR_RESET << " : " << re.what() << std::flush;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
	
}

	/********** Core **********/

	// Save time functions
time_t getLastSaveTime (std::string serv, std::string map) {
	time_t lastsavetime = MC_LASTSAVETIME_NOSAVE;
	DIR* map_dir = ::opendir( _s(IOSLAVES_MINECRAFT_MASTER_DIR,"/",serv,"/maps/",map) );
	if (map_dir == NULL) {
		if (errno == ENOENT) return MC_LASTSAVETIME_NOSAVE;
		throw xif::sys_error("can't open server world save folder to list saves");
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
		} catch (const std::runtime_error) { continue; }
	}
	::closedir(map_dir);
	return lastsavetime;
}

	// Launch ioslaves-master and connect
socketxx::io::simple_socket<socketxx::base_socket> getConnection (std::string slave, std::string servname, minecraft::op_code opp, timeval timeout, bool autostart, bool autoservice) {
	bool secondtry = false;
	std::function<socketxx::io::simple_socket<socketxx::base_socket>(void)> get_sock = [&]() -> socketxx::io::simple_socket<socketxx::base_socket> {
		try {
			try {
				__log__ << LOG_ARROW << "Connecting to '" << slave << "'..." << std::flush;
				return iosl_master::slave_api_service_connect(slave, $master_id, "minecraft", TIMEOUT_CONNECT);
			} catch (const master_err& e) {
				if (e.is_ioslaves_err() and e.o == ioslaves::answer_code::BAD_STATE and $granmaster and autoservice) {
					__log__ << LOG_ARROW << "Minecraft service seems to be off. Starting it..." << std::flush;
					socketxx::io::simple_socket<socketxx::base_netsock> sock = iosl_master::slave_connect(slave, 0);
					iosl_master::slave_command_auth(sock, $master_id, ioslaves::op_code::SERVICE_START, _S($master_id,'.',slave));
					sock.o_str("minecraft");
					ioslaves::answer_code answ = (ioslaves::answer_code)sock.i_char();
					if (answ != ioslaves::answer_code::OK) {
						__log__ << LOG_ARROW_ERR << "Failed to start Minecraft service : " << ioslaves::getAnswerCodeDescription(answ) << std::flush;
						throw answ;
					}
					return iosl_master::slave_api_service_connect(slave, $master_id, "minecraft", TIMEOUT_CONNECT);
				} else 
					throw;
			}
		} catch (const master_err& e) {
			__log__ << LOG_ARROW_ERR << "ioslaves-master error : " << e.what() << std::flush;
			if (e.ret == EXIT_FAILURE_DOWN and not secondtry and autostart and $granmaster) {
				time_t time_up = 0;
				try {
					time_up = iosl_master::slave_start($slave_id, $master_id);
				} catch (const std::exception& e) {
					__log__ << LOG_AROBASE_ERR << "Power up error : " << e.what() << std::flush;
					EXIT_FAILURE = EXIT_FAILURE_EXTERR;
					throw EXCEPT_ERROR_IGNORE;
				}
				__log__ << LOG_AROBASE << "Please wait " << time_up << "s for slave starting..." << std::flush;
				::sleep((uint)time_up);
				secondtry = true;
				return get_sock();
			} else {
				if (e.is_ioslaves_err()) 
					throw e.o;
				EXIT_FAILURE = EXIT_FAILURE_CONN;
				throw EXCEPT_ERROR_IGNORE;	
			}
		}
	};
	socketxx::io::simple_socket<socketxx::base_socket> sock = get_sock();
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
	ioslaves::answer_code o;
	while ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) {
		if (o == ioslaves::answer_code::WANT_REPORT)
			handleReportRequest(sock, slave);
		else throw o;
	}
	sock.set_read_timeout(TIMEOUT_COMM);
	return sock;
}

	// File retreiving progression callback
void retreivingProgressionShow (size_t done, size_t totsz) {
	std::function<void(std::string)> send_websocket = [&] (std::string str) {
		str = std::string("[trsf]") + str;
		int rs; errno = 0;
		rs = nopoll_conn_send_text($websocket_conn, str.c_str(), str.length());
		if (rs != (int)str.length()) {
			nopoll_conn_close($websocket_conn);
			$websocket_conn = NULL;
			std::cerr << LOG_AROBASE_ERR << "WebLog stopped : Websocket error : " << ::strerror(errno) << std::endl;
		}
	};
	static timeval beg, last, now;
	::gettimeofday(&now, NULL);
	if (totsz == 0) {
		if (done == 0) {
			beg = last = now;
			if ($websocket_conn != NULL) 
				send_websocket("init");
		} else {
			if ($websocket_conn != NULL) 
				send_websocket("finish");
		}
		return;
	}
	uint percent = (uint)lroundf( done*100.f/totsz );
	if (optctx::interactive) {
		std::stringstream buf;
		buf << " " << percent << "% - " << done/1024 << "K/" << totsz/1024 << "K  ";
		std::cout << buf.str() << std::flush;
		std::cout << std::string(buf.str().length(), '\b') << "\033[K" << std::flush;
	}
	if ($websocket_conn != NULL and (now.tv_sec != last.tv_sec or now.tv_usec-last.tv_usec > 100000 or totsz == 0)) 
		send_websocket(::ixtoa(percent));
	last = now;
}

	// Retrieve server folder save
void acceptFileSave (socketxx::io::simple_socket<socketxx::base_socket> sock, std::string servname, std::string mapname, std::string slave, bool truesave) {
	__log__ << LOG_AROBASE << "Retrieving world save '" << mapname << "' of server '" << servname << "'" << std::flush;
	int r;
	time_t lastsavetime_dist = sock.i_int<int64_t>();
	time_t lastsavetime_local = getLastSaveTime(servname, mapname);
	if ($refuse_save) {
		__log__ << LOG_AROBASE_ERR << "Won't accept save : refuse option activated" << std::flush;
		sock.o_bool(false);
		return;
	}
	if (lastsavetime_dist < lastsavetime_local) {
		__log__ << LOG_AROBASE_ERR << "Won't accept save : distant save (" << lastsavetime_dist << ") is older than last local save (" << lastsavetime_local << ")" << std::flush;
		sock.o_bool(false);
		return;
	}
	std::string folder_saves = _S( IOSLAVES_MINECRAFT_MASTER_DIR,"/",servname,"/maps/",mapname );
	r = ::mkdir(folder_saves.c_str(), S_IRWXU|S_IRWXG);
	if (r == -1 and errno != EEXIST and errno != EISDIR) {
		__log__ << LOG_AROBASE_ERR << " Can't create folder for saves of world " << mapname << " to retrieve save : " << ::strerror(errno) << std::flush;
		sock.o_bool(false);
		return;
	}
	std::string savepath = _S( folder_saves,'/',mapname,'_',::ixtoa(lastsavetime_dist,IX_HEX_MAJ),".zip" );
	if (::access(savepath.c_str(), F_OK) == 0) {
		__log__ << LOG_AROBASE_ERR << "Won't accept save : already exists for " << lastsavetime_local << std::flush;
		sock.o_bool(false);
		return;
	}
	sock.o_bool(true);
	sock.set_read_timeout(TIMEOUT_ZIP_DELAY);
	fd_t save_f = ::open(savepath.c_str(), O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW, MC_MAP_PERM);
	if (save_f == -1)
		throw xif::sys_error("can't open map save file");
	RAII_AT_END_L( ::close(save_f) );
	try {
	                              retreivingProgressionShow(0,0);
	sock.i_file(save_f, std::bind(retreivingProgressionShow, std::placeholders::_1,std::placeholders::_2));
	                              retreivingProgressionShow(1,0);
	} catch (const socketxx::error&) {
		::close(save_f);
		::unlink(savepath.c_str());
		throw;
	}
	sock.set_read_timeout(TIMEOUT_COMM);
	ioslaves::infofile_set(_s(folder_saves,"/lastsave_from"), slave);
	ioslaves::infofile_set(_s(folder_saves,"/lastsave"), ::ixtoa(lastsavetime_dist));
	__log__ << LOG_AROBASE_OK << "Retrieval done !";
	if (truesave) {
		__log__ << " Save " << lastsavetime_dist << " set as true save from " << slave << std::flush;
		ioslaves::infofile_set(_s(folder_saves,"/truesave"), "true");
	} else 
		__log__ << std::flush;
}

	// Process a report request (stopping, crashing...) of slave
void handleReportRequest (socketxx::io::simple_socket<socketxx::base_socket> sock, std::string slave) {
	int r;
	std::string servname = sock.i_str();
	__log__ << LOG_AROBASE << "Handling stop report request for server '" << servname << "' from slave " << slave << "..." << std::flush;
	minecraft::whyStopped why_stopped = (minecraft::whyStopped)sock.i_char();
	const char* reason = NULL;
	switch (why_stopped) {
		case minecraft::whyStopped::DESIRED_INTERNAL: reason = "Stopped automatically by ioslavesd-minecraft"; break;
		case minecraft::whyStopped::DESIRED_MASTER: reason = "Stopped by a master"; break;
		case minecraft::whyStopped::ITSELF: reason = "Minecraft server stopped itself"; break;
		case minecraft::whyStopped::ERROR_INTERNAL: reason = "Killed or halted by force"; break;
		case minecraft::whyStopped::NOT_STARTED: reason = "Server was not even started"; break;
		default: reason = "Unknown";
	}
	bool gracefully_stopped = sock.i_bool();
	bool current_state_running = sock.i_bool();
	std::string map_to_save = sock.i_str();
	__log__ << "Server was stopped " << (gracefully_stopped?"":"un") << "gracefully. Reason : " << reason << ".";
	if (not $granmaster or ($refuse_save and ($worldname.empty() or $worldname != map_to_save))) {
		__log__ << std::flush << LOG_AROBASE_ERR << "Refusing report request" << std::flush;
		sock.o_bool(false);
		return;
	}
	r = ::access( _s(IOSLAVES_MINECRAFT_MASTER_DIR,'/',servname), X_OK);
	if (r == -1) {
		__log__ << std::flush << LOG_AROBASE_ERR << "Can't accept report request : unable to access server folder" << std::flush;
		sock.o_bool(false);
		return;
	}
	if (::getRunningOnSlave(servname).empty())
		__log__ << std::flush << COLOR_YELLOW << "Warning ! Locally, server was stopped. Maybe an another master started this server. " << COLOR_RESET << std::flush;
	fd_t lockf = -1;
	std::string lockpath = _S( IOSLAVES_MINECRAFT_MASTER_DIR,'/',servname,"/_mcmaster.lock" );
	if (servname != $server_name) {
		lockf = ::open(lockpath.c_str(), O_CREAT|O_RDONLY|O_EXCL|O_NOFOLLOW, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
		if (lockf == -1 and errno == EEXIST) {
			__log__ << std::flush << LOG_AROBASE_ERR << "Can't accept report request : server directory is already locked" << std::flush;
			sock.o_bool(false);
			return;
		}
		if (lockf == -1) throw xif::sys_error("create lock file");
	}
	RAII_AT_END({
		if (lockf != -1) {
			::close(lockf);
			::unlink(lockpath.c_str());
		}
	});
	if (not map_to_save.empty()) 
		__log__ << " Saving world '" << map_to_save << "'..." << std::flush;
	else __log__ << std::flush;
	bool true_save = true;
	if (current_state_running) {
		::setRunningOnSlave(servname, slave);
		true_save = false;
	} else {
		std::string local_running_on = ::getRunningOnSlave(servname);
		if (local_running_on == slave) {
			true_save = true; // really ?
			::setRunningOnSlave(servname, "");
		} else {
			true_save = false;
		}
	}
	sock.o_bool(true);
	if (not map_to_save.empty())
		acceptFileSave(sock, servname, map_to_save, slave, true_save);
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
	__log__ << "Marking server '" << serv << "' as ";
	if (running_on_slave.empty()) __log__ << " closed." << std::flush;
	else                          __log__ << " opened on slave '" << running_on_slave << "'." << std::flush;
	ioslaves::infofile_set(filename.c_str(), running_on_slave);
}

inline bool checkSlaveStatus (std::string slave) {
	bool isSlaveRunning = iosl_master::slave_test(slave);
	if (not isSlaveRunning) 
		__log__ << "Slave '" << slave << "' is unreachable." << std::flush;
	return isSlaveRunning;
}

inline void granmasterSlaveSet () {
	if ($granmaster) {
		std::string running_on_slave = ::getRunningOnSlave($server_name);
		if (running_on_slave.empty()) {
			__log__ << LOG_ARROW_ERR << "Server '" << $server_name << "' is (probably) not running !" << std::flush;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		}
		$slave_id = running_on_slave;
	}
}

void verifyMapList (std::string slave_id, std::string server_name, socketxx::io::simple_socket<socketxx::base_socket> sock) {
	int r;
	try {
		size_t sz = sock.i_int<uint32_t>();
		while (sz --> 0) {
			std::string map = sock.i_str();
			time_t lastsave = sock.i_int<uint64_t>();
			bool fixed = sock.i_bool();
			if (not $granmaster or $refuse_save) {
				sock.o_char((char)ioslaves::answer_code::OK);
				continue;
			}
			std::string map_folder = _S( IOSLAVES_MINECRAFT_MASTER_DIR,"/",server_name,"/maps/",map );
			bool want_get = false;
			r = ::access(map_folder.c_str(), F_OK);
			if (r == -1) {
				__log__ << COLOR_YELLOW << "Warning !" << COLOR_RESET << " World '" << map << "' of server '" << server_name << "' on slave '" << slave_id << "' doesn't exist locally !" << std::flush;
				r = ::mkdir(map_folder.c_str(), S_IRWXU|S_IRWXG);
				if (r == -1) {
					__log__ << NICE_WARNING << COLOR_YELLOW << "Warning !" << COLOR_RESET << " Can't create folder for saves of world " << map << " to retrieve save : " << ::strerror(errno) << std::flush;
					continue;
				}
				ioslaves::infofile_set(_s(map_folder,"/truesave"), "false");
				ioslaves::infofile_set(_s(map_folder,"/lastsave_from"), slave_id);
				__log__ << LOG_AROBASE_OK << "Saves folder of world '" << map << "' created." << std::flush;
				if (lastsave != 0)
					want_get = true;
			} else {
				time_t lastsave_local = getLastSaveTime(server_name, map);
				if (lastsave_local < lastsave) {
					__log__ << COLOR_YELLOW << "Warning !" << COLOR_RESET << " Slave '" << slave_id << "' have a more recent version of world '" << map << "'." << std::flush;
					want_get = true;
				}
			}
			std::string fixed_on = ioslaves::infofile_get(_s( map_folder,"/fixed_on" ), true);
			if ((not fixed_on.empty() and fixed_on == slave_id and not fixed) or (fixed and fixed_on.empty())) {
				__log__ << COLOR_RED << "SEVERE : World '" << map << "' is not of the same fixiness on slave '" << slave_id << "' !" << COLOR_RESET << std::flush;
				sock.o_char((char)ioslaves::answer_code::OK);
				continue;
			}
			if (want_get) {
				sock.o_char((char)ioslaves::answer_code::WANT_GET);
				acceptFileSave(sock, server_name, map, slave_id, false);
			} else
				sock.o_char((char)ioslaves::answer_code::OK);
		}
	} catch (const socketxx::error& e) {
		__log__ << LOG_AROBASE_ERR << "Network error while getting world list for server " << server_name << " : " << e.what() << std::flush;
		return;
	}
}

/** ---------------------------- STATUS ---------------------------- **/

void MServStatus () {
	__log__ << LOG_ARROW << "Updating status for server '" << $server_name << "'..." << std::flush;
	int32_t n_players = -1;
	time_t zero_players_since = 0;
	in_port_t s_port = 0;
	bool s_is_perm_map = true;
	time_t s_time_start = 0;
	std::string s_map = "";
	auto _retrieve_status_info_ = [&] (std::string slave, socketxx::io::simple_socket<socketxx::base_socket>& sock, bool& $status) {
		$status = sock.i_bool();
		if ($status) {
			sock.o_bool(true);
			s_is_perm_map = sock.i_bool();
			s_map = sock.i_str();
			s_time_start = sock.i_int<uint64_t>();
			n_players = sock.i_int<int32_t>();
			zero_players_since = sock.i_int<uint32_t>();
			s_port = sock.i_int<in_port_t>();
			if (not optctx::interactive)
				std::cout << std::endl << xif::polyvar(xif::polyvar::map({{"running",true},
				                                                          {"slave",slave},
				                                                          {"players",n_players},
				                                                          {"zeropl_min",(zero_players_since == 0 ? xif::polyvar() : xif::polyvar((::time(NULL)-zero_players_since)/60))},
				                                                          {"port",s_port},
				                                                          {"is_perm_map",s_is_perm_map},
				                                                          {"map",s_map},
				                                                          {"start_time",s_time_start}
				})).to_json() << std::endl;
		}
		verifyMapList(slave, $server_name, sock);
	};
	if ($granmaster) {
		std::string $local_slave_id = ::getRunningOnSlave($server_name);
		if (not $local_slave_id.empty()) {
			__log__ << "Checking on slave '" << $local_slave_id << "' on which server should be running now..." << std::flush;
			bool $status;
			std::function<void(uint)> tryGetStatus = [&] (uint n) -> void {
				if (n == 0) {
					$status = false;
					__log__ << NICE_WARNING << COLOR_YELLOW << "WARNING" << COLOR_RESET << " : Could not connect to '" << $local_slave_id << "' on which server was known to be running on ! " << 
					           COLOR_YELLOW << " ** Please recheck later !" << COLOR_RESET << std::flush;
					return;
				}
				try {
					auto sock = getConnection($local_slave_id, $server_name, minecraft::op_code::SERV_STAT, {2,0}, false, true);
					std::string $re_local_slave_id = ::getRunningOnSlave($server_name);
					if ($local_slave_id != $re_local_slave_id) 
						__log__ << "After report, the server is now closed" << std::flush;
					_retrieve_status_info_($local_slave_id, sock, $status);
				} catch (const socketxx::error& e) {
					__log__ << NICE_WARNING << "Network error while refreshing status : " << e.what() << std::flush;
					::sleep(3);
					tryGetStatus(n-1);
				} catch (...) {
					__log__ << NICE_WARNING << "Failed to connect to slave ! " << std::flush;
					::sleep(5);
					tryGetStatus(n-1);
				}
			}; tryGetStatus(20/*trials*/);
			if ($status) {
				__log__ << LOG_ARROW_OK << "Yes, server is running on slave '" << $local_slave_id << "'." << std::flush;
				::setRunningOnSlave($server_name, $local_slave_id);
			} else {
				__log__ << LOG_ARROW_ERR << "Erm... No, server isn't running on slave '" << $local_slave_id << "'." << std::flush;
				#warning TO DO : check on dedicated slave of all maps
				if (not $slave_id.empty() and $local_slave_id != $slave_id) {
					goto __check_on_user_slave;
				} else {
					::setRunningOnSlave($server_name, "");
					if (not optctx::interactive)
						std::cout << std::endl << xif::polyvar(xif::polyvar::map({{"running",false}})).to_json() << std::endl;
				}
			}
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
				auto sock = getConnection($slave_id, $server_name, minecraft::op_code::SERV_STAT, {2,0}, false, true);
				_retrieve_status_info_($slave_id, sock, $status);
			} catch (const std::runtime_error& e) {
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
			if (not $local_slave_id.empty()) 
				::setRunningOnSlave($server_name, "");
			if (not optctx::interactive)
				std::cout << std::endl << xif::polyvar(xif::polyvar::map({{"running",false}})).to_json() << std::endl;
		}
	} else {
		auto sock = getConnection($slave_id, $server_name, minecraft::op_code::SERV_STAT, {2,0}, false, false);
		bool $status;
		_retrieve_status_info_($slave_id, sock, $status);
		__log__ << LOG_ARROW_OK << "Server '" << $server_name << "' on slave '" << $slave_id << "' is " << ($status?"running":"NOT running") << std::flush;
		if ($status) {
			__log__ << n_players << " players connected" << std::flush;
		} else {
			if (not optctx::interactive)
				std::cout << std::endl << xif::polyvar(xif::polyvar::map({{"running",false}})).to_json() << std::endl;
		}
	}
}

/** ---------------------------- PERMANENTIZE ---------------------------- **/

void MServPerm () {
	__log__ << LOG_ARROW << "Permanentize map on server " << $server_name << "..." << std::flush;
	granmasterSlaveSet();
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::PERMANENTIZE, {2,0}, false, false);
	std::string map = sock.i_str();
	ioslaves::answer_code o;
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << LOG_ARROW_OK << "Done on map '" << map << "' !" << std::flush;
	if (not $granmaster) 
		return;
	std::string folder_saves = _S( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",map );
	if (::access(folder_saves.c_str(), F_OK) == 0) {
		__log__ << COLOR_YELLOW << "World folder '" << map << "' already exists." << COLOR_RESET << " Map will be saved inside !" << std::flush;
	}
}

/** ---------------------------- NEW FTP SESSION ---------------------------- **/

void MServFTPSess () {
	__log__ << LOG_ARROW << "Create FTP session for user '" << $ftp_user << "' on server " << $server_name << " for current running world..." << std::flush;
	granmasterSlaveSet();
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::FTP_SESSION, {2,0}, false, false);
	std::string worldname = sock.i_str();
	sock.o_str($ftp_user);
	sock.o_str($ftp_hash_passwd);
	bool fixed = not ioslaves::infofile_get(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",worldname,"/fixed_on" ), true).empty();
	uint32_t sess_validity = fixed ? 60*60*24 : 60*15;
	sock.o_int<uint32_t>(sess_validity);
	ioslaves::answer_code o;
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	std::string addrstr = sock.i_str();
	__log__ << LOG_ARROW_OK << "FTP session created for " << sess_validity << "s on map " << worldname << "." << std::flush;
	__log__ << "FTP server address : " << addrstr << std::flush;
	if (not optctx::interactive)
	std::cout << std::endl << addrstr;
}

/** ---------------------------- DELETE MAP ---------------------------- **/

void MServDelMap () {
	__log__ << LOG_ARROW << "Delete world '" << $worldname << "' on server " << $server_name << "..." << std::flush;
	if ($slave_id.empty()) {
		std::string lastsave_from = ioslaves::infofile_get(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",$worldname,"/lastsave_from" ), true);
		if (lastsave_from.empty() or !ioslaves::validateSlaveName(lastsave_from)) {
			__log__ << LOG_ARROW_ERR << "No info about slave which would have the world on." << std::flush;
			return;
		}
		$slave_id = lastsave_from;
	}
	__log__ << "Trying on " << $slave_id << "..." << std::flush;
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::DELETE_MAP, {1,0}, false, true);
	sock.o_str($worldname);
	ioslaves::answer_code o;
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << LOG_ARROW_OK << "Done !" << std::flush;
}

/** ---------------------------- FIX/UNFIX WORLD ---------------------------- **/

void MServFixMap () {
	ioslaves::answer_code o;
	std::string fixed_on = ioslaves::infofile_get(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",$worldname,"/fixed_on" ), true);
	if (fixed_on.empty() and $fixmap == false) {
		__log__ << LOG_ARROW_ERR << "World '" << $worldname << "' of server '" << $server_name << "' is not fixed." << std::flush;
		throw EXCEPT_ERROR_IGNORE;
	}
	if (not fixed_on.empty() and $fixmap == true) {
		__log__ << LOG_ARROW_ERR << "World '" << $worldname << "' of server '" << $server_name << "' is already fixed on slave '" << fixed_on << "'." << std::flush;
		throw EXCEPT_ERROR_IGNORE;
	}
	if ($fixmap == true) {
		std::string running_on_slave = ::getRunningOnSlave($server_name);
		if ($slave_id.empty()) {
			if (not $granmaster) 
				try_help("--fix-world : slave ID must be defined\n");
			if (running_on_slave.empty()) {
				__log__ << LOG_ARROW_ERR << "Fixing world '" << $worldname << "' of server '" << $server_name << "' : can't choose a slave for you !" << std::flush;
				throw EXCEPT_ERROR_IGNORE;
			}
			$slave_id = running_on_slave;
		} else
			if (not running_on_slave.empty() and running_on_slave != $slave_id) {
				__log__ << LOG_ARROW_ERR << "Server '" << $server_name << "' is running on slave '" << running_on_slave << "' : world can't be fixed on slave '" << $slave_id << "'." << std::flush;
				EXIT_FAILURE = EXIT_FAILURE_IOSL;
				throw EXCEPT_ERROR_IGNORE;
			}
		__log__ << LOG_ARROW << "Fixing world '" << $worldname << "' of server " << $server_name << " on slave '" << $slave_id << "'..." << std::flush;
		auto sock = getConnection($slave_id, $server_name, minecraft::op_code::FIX_MAP, {2,0}, false, true);
		sock.o_str($worldname);
		sock.o_bool($fixmap);
		if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
			throw o;
		time_t lastsavetime_distant = (time_t)sock.i_int<uint64_t>();
		time_t lastsavetime_local = getLastSaveTime($server_name, $worldname);
		if (lastsavetime_distant - lastsavetime_local < -MINECRAFT_SERV_MASTER_MAX_DELAY_CONSIDERED_EQUAL) {
			sock.o_char((char)ioslaves::answer_code::WANT_SEND);
			__log__ << LOG_ARROW_ERR << "World '" << $worldname << "' is older on slave '" << $slave_id << "' than locally." << std::flush;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		}
		sock.o_char((char)ioslaves::answer_code::OK);
		if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
			throw o;
		ioslaves::infofile_set(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",$worldname,"/fixed_on" ), $slave_id);
		__log__ << LOG_ARROW_OK << "World '" << $worldname << "' is fixed on slave '" << $slave_id << "'." << std::flush;
	} else
	if ($fixmap == false) {
		if (not $slave_id.empty() and fixed_on != $slave_id) {
			__log__ << LOG_ARROW_ERR << "World '" << $worldname << "' is fixed on slave '" << fixed_on << "', not on slave '" << $slave_id << "' !" << std::flush;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		}
		__log__ << LOG_ARROW << "Unfixing world '" << $worldname << "' of server " << $server_name << " from slave '" << fixed_on << "'..." << std::flush;
		auto sock = getConnection($slave_id, $server_name, minecraft::op_code::FIX_MAP, {2,0}, false, true);
		sock.o_str($worldname);
		sock.o_bool($fixmap);
		if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
			throw o;
		__log__ << "Unfixing proceeds..." << std::flush;
		if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
			throw o;
		acceptFileSave(sock, $server_name, $worldname, $slave_id, true);
		ioslaves::infofile_set(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",$worldname,"/lastsave" ), ::ixtoa(::time(NULL)));
		if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
			throw o;
		ioslaves::infofile_set(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",$worldname,"/fixed_on" ), std::string());
		__log__ << LOG_ARROW_OK << "World '" << $worldname << "' is no more fixed." << std::flush;
	}
}

/** ---------------------------- FORCE WORLD SAVING ---------------------------- **/

void MServSaveMap () {
	__log__ << LOG_ARROW << "Saving world '" << $worldname << "' of server " << $server_name << "..." << std::flush;
	if ($slave_id.empty()) {
		std::string lastsave_from = ioslaves::infofile_get(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",$worldname,"/lastsave_from" ), true);
		if (lastsave_from.empty() or !ioslaves::validateSlaveName(lastsave_from)) {
			__log__ << LOG_ARROW_ERR << "No info about slave which would have the world on." << std::flush;
			return;
		}
		$slave_id = lastsave_from;
	}
	__log__ << "Retrieving save from slave " << $slave_id << "..." << std::flush;
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::SAVE_MAP, {4,0}, true, true);
	sock.o_str($worldname);
	ioslaves::answer_code o;
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) 
		throw o;
	acceptFileSave(sock, $server_name, $worldname, $slave_id, false);
	__log__ << LOG_ARROW_OK << "Done !" << std::flush;
}

/** ---------------------------- START ---------------------------- **/

void MServStart () {
	__log__ << LOG_ARROW << "Starting server '" << $server_name << "'..." << std::flush;
	int r;
	bool autoselect_slave = $hint;
	std::string fixed_on = ioslaves::infofile_get(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",$worldname,"/fixed_on" ), true);
	if (not fixed_on.empty()) {
		autoselect_slave = false;
		if ($slave_id.empty()) 
			$slave_id = fixed_on;
		else if ($slave_id != fixed_on) {
			__log__ << LOG_AROBASE_ERR << "Can't start world '" << $worldname << "' on slave '" << $slave_id << "' : world is fixed on slave '" << fixed_on << "'." << std::flush;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		}
		__log__ << "Chose slave '" << fixed_on << "' on which world '" << $worldname << "' is fixed." << std::flush;
	}
	std::vector<iosl_dyn_slaves::slave_info> slaves;
	bool infos_gathered = false;
	std::vector<std::string> excluded_slaves;
	socketxx::io::simple_socket<socketxx::base_socket>* sock;
	goto _try_start;
_retry_start:
	if (autoselect_slave) {
		__log__ << LOG_ARROW << "Trying another slave..." << std::flush;
		excluded_slaves.push_back($slave_id);
		$slave_id.clear();
		goto _try_start;
	} else {
		if (fixed_on.empty()) 
			__log__ << LOG_AROBASE_ERR << "Try an another slave or let the slave selection do its job." << std::flush;
		else 
			__log__ << LOG_AROBASE_ERR << "Sorry, slave '" << $slave_id << "' is not available." << std::flush;
		throw EXCEPT_ERROR_IGNORE;
	}
_try_start:
	if ($granmaster) {
		std::string running_on_slave = ::getRunningOnSlave($server_name);
		if (not running_on_slave.empty()) {
			__log__ << LOG_ARROW_ERR << "Server '" << $server_name << "' is probably running on slave '" << running_on_slave << "'" << std::flush;
			__log__ << "Checking on slave '" << running_on_slave << "' on which server should be running now..." << std::flush;
			bool $status = checkSlaveStatus(running_on_slave);
			if ($status) {
				auto sock = getConnection(running_on_slave, $server_name, minecraft::op_code::SERV_STAT, {2,0}, false, true);
				if (running_on_slave != ::getRunningOnSlave($server_name)) {
					__log__ << LOG_ARROW << "Well... After report, server is now closed. Launching server..." << std::flush;
					goto _continue_launch;
				}
				$status = sock.i_bool();
				if ($status) sock.o_bool(false);
				verifyMapList(running_on_slave, $server_name, sock);
			}
			if ($status) {
				__log__ << LOG_ARROW_ERR << "Yes, server is already running on slave '" << running_on_slave << "'." << std::flush;
				EXIT_FAILURE = EXIT_FAILURE_IOSL;
				throw EXCEPT_ERROR_IGNORE;
			} else {
				__log__ << LOG_ARROW_ERR << "Erm... No, server isn't running on slave '" << running_on_slave << "'." << std::flush;
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
			using namespace iosl_dyn_slaves;
			std::string lastsave_from = ioslaves::infofile_get(_s( IOSLAVES_MINECRAFT_MASTER_DIR,"/",$server_name,"/maps/",$worldname,"/lastsave_from" ), true);
			if (!ioslaves::validateSlaveName(lastsave_from)) lastsave_from.clear();
			if (not $forced_file.empty()) lastsave_from.clear();
			if (not lastsave_from.empty())
				 __log__ << "Last slave who ran this world : " << lastsave_from << std::flush;
			if ($mean_cpu == 0.f) $mean_cpu = $needed_cpu/2.f;
			try {
			if (not infos_gathered) {
				__log__ << LOG_AROBASE << "Gathering slaves status and infos..." << std::flush;
				slaves = iosl_dyn_slaves::gather_infos({ "dyn-hosting" });
				for (iosl_dyn_slaves::slave_info& slave_info : slaves) {
					try {
						slave_info.sl_usable_mem += MC_SWAP_FACTOR*(float)(int16_t)slave_info._sl_raw_infos["system"]["mem_swap"];
					} catch (...) {}
				}
				infos_gathered = true;
			}
			iosl_dyn_slaves::select_slaves(slaves,
				"minecraft", 
				$needed_ram, $needed_cpu,
				$needed_eff, $mean_cpu, $threads_num,
				false,
				[&] (const slave_info& info) -> points_t {
					for (const std::string& sl : excluded_slaves) 
						if (info.sl_name == sl) return INT32_MIN;
					if (lastsave_from == info.sl_name) return +200;
					uint32_t net_upload = info.sl_fixed_indices.at("net_upload");
					#define NET_Frontier 100
					if (net_upload < NET_Frontier) 
						return (net_upload - NET_Frontier);
					#define NET_MaxPoints 100
					#define NET_InvF 61000.f
					#define NET_LinF 0.0023f
					#define NET_StepPTs 100
					#define NET_InvShift 508.5f
					return std::max<points_t>( NET_InvF/(-net_upload-NET_InvShift) + NET_StepPTs + NET_LinF*net_upload , NET_MaxPoints );
				}
			);
			{ // Nice html table
				std::ostringstream t;
				t << "<table>" << std::setprecision(2);
				t << "<tr> <th>slave</th> <th>stat</th> <th>∆ram</th> <th>pt.ram</th> <th>q.proc</th> <th>pt.proc</th> <th>pw.add</th> <th>pt.eff</th> <th>pt.wait</th> <th>pt.oth</th> <th>pt.total</th> </tr>";
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
					t << "<td>+" << std::get<4>(info._sl_categs_infos) << "W</td>";
					SlSelTab_PrintPt(5);
					SlSelTab_PrintPt(6);
					SlSelTab_PrintPt(7);
					t << "<td>" << info.sl_total_points << "</td>";
				bye:
					t << "</tr>";
				}
				t << "</table>";
				__log__ << t.str() << std::flush;
			}
			if (slaves.size() == 0 or slaves.front().sl_total_points == INT32_MIN or slaves.front().sl_total_points < 0) {
				__log__ << LOG_ARROW_ERR << "Sorry, no slave available... " << std::flush;
				throw EXCEPT_ERROR_IGNORE;
			}
			$slave_id = slaves.front().sl_name;
			__log__ << LOG_AROBASE_OK << "Ok, we choose " << $slave_id << " with " << slaves.front().sl_total_points << " points" << std::flush;
			if (slaves.front().sl_status == -1) {
				try {
					iosl_master::slave_start($slave_id, $master_id);
				} catch (const std::exception& e) {
					__log__ << LOG_AROBASE_ERR << "Power up error : " << e.what() << std::flush;
					if (not $granmaster) EXCEPT_ERROR_IGNORE;
					goto _retry_start;
				}
				uint wait_delay = slaves.front().sl_start_delay;
				__log__ << LOG_AROBASE << "Please wait " << wait_delay << "s for slave starting..." << std::flush;
				::sleep(wait_delay);
			}
			} catch (const std::exception& e) {
				__log__ << LOG_AROBASE_ERR << "Error while selecting slave : " << e.what() << std::flush;
				throw EXCEPT_ERROR_IGNORE;
			}
		}
	}
	try {
		sock = new socketxx::io::simple_socket<socketxx::base_socket> (
			getConnection($slave_id, $server_name, minecraft::op_code::START_SERVER, {2,0}, !autoselect_slave or $hint, true)
		);
	} catch (const ioslaves::answer_code) {
		if (not $granmaster) throw;
		goto _retry_start;
	}
	__log__ << "Sending infos..." << std::flush;
	sock->o_char((char)$start_serv_type);
	sock->o_str($start_jar_ver);
	sock->o_int<uint16_t>($needed_ram);
	sock->o_bool($start_is_perm);
	__log__ << " - " << ($start_is_perm?"permanent world ":($start_temp_perm?"temporary map with world save":"temporary map")) << " : " << $worldname << std::flush;
	if (not $start_is_perm)
		sock->o_bool($start_temp_perm);
	if ($autoclose_time != 0) 
		__log__ << " - autoclose time : " << $autoclose_time/60 << "min" << std::flush;
	else 
		__log__ << " - no autoclose" << std::flush;
	sock->o_int<uint32_t>((uint32_t)$autoclose_time);
	__log__ << " - view distance : " << (int)$mc_viewdist << std::flush;
	sock->o_int<uint8_t>($mc_viewdist);
	__log__ << " - time estimation : " << $needed_time/60 << "min" << std::flush;
	sock->o_int<uint32_t>((uint32_t)$needed_time);
	sock->o_str($worldname);
	time_t lastsavetime;
	if (not $forced_file.empty()) {
		$refuse_save = false;
		lastsavetime = MC_LASTSAVETIME_FORCE;
	} else {
		if ($granmaster and $start_is_perm) lastsavetime = getLastSaveTime($server_name, $worldname);
		else lastsavetime = MC_LASTSAVETIME_NOSAVE;
	}
	__log__ << " - last-save-time : " << lastsavetime << std::flush;
	sock->o_int<int64_t>(lastsavetime);
	sock->o_bool($start_earlyconsole);
	if ($port != 0) 
		__log__ << " - minecraft port : " << $port << std::flush;
	sock->o_int<uint16_t>($port);
	sock->o_int<uint8_t>((uint8_t)$additional_ports.size());
	for (size_t i = 0; i < $additional_ports.size(); i++) 
		sock->o_int<uint16_t>($additional_ports[i]);
	ioslaves::answer_code o;
	if ((o = (ioslaves::answer_code)sock->i_char()) != ioslaves::answer_code::OK) {
		if (o == ioslaves::answer_code::BAD_STATE and $granmaster) {
			__log__ << NICE_WARNING << COLOR_YELLOW << "Server is already opened on slave !" << COLOR_RESET << std::flush;
			::setRunningOnSlave($server_name, $slave_id);
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		} else if (o == ioslaves::answer_code::LACK_RSRC) {
			__log__ << LOG_AROBASE_ERR << "Lacking ressources on slave '" << $slave_id << "' : can't start server !" << std::flush;
			if (not $granmaster) throw EXCEPT_ERROR_IGNORE;
			goto _retry_start;
		} else
			throw o;
	}
	in_port_t port = sock->i_int<uint16_t>();
	__log__ << LOG_AROBASE << "Waiting queries or ack from minecraft service" << std::flush;
	while ((o = (ioslaves::answer_code)sock->i_char()) != ioslaves::answer_code::OK) {
		if (o == ioslaves::answer_code::EXISTS and not $start_is_perm) {
			__log__ << LOG_ARROW_ERR << "A permanent world named '" << $worldname << "' already exists on slave " << NICE_WARNING << " Delete it if wanted." << std::flush;
			if (not $granmaster) throw o;
			__log__ << LOG_AROBASE << "Refreshing status..." << std::flush;
			auto sock = getConnection($slave_id, $server_name, minecraft::op_code::SERV_STAT, {1,0}, false, false);
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
				else if ($start_serv_type == minecraft::serv_type::BUNGEECORD) jar_prefix = "mc_bungeecord_";
				else { sock->o_bool(false); continue; }
				std::string jar_name, jar_path = _s( IOSLAVES_MINECRAFT_MASTER_JAR_DIR,'/',(jar_name=_s(jar_prefix,jar_ver,".jar")) );
				r = ::access(jar_path.c_str(), R_OK);
				if (r == -1) {
					sock->o_bool(false);
					__log__ << LOG_ARROW_ERR << "Minecraft jar '" << jar_name << "' not found for sending to slave" << std::flush;
					EXIT_FAILURE = EXIT_FAILURE_EXTERR;
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
					EXIT_FAILURE = EXIT_FAILURE_SYSERR;
					throw EXCEPT_ERROR_IGNORE;
				}
				sock->o_bool(true);
				sock->o_file(bigfile_path.c_str());
			} else if ($granmaster) {
				__log__ << LOG_AROBASE << " Want get map (" << (char)what << ") : ";
				if (not $start_is_perm) {
					__log__ << "sending temporary map " << $worldname << std::flush;
					if (what != minecraft::transferWhat::MAP) { sock->o_bool(false); continue; }
					std::string tempmap_path = _S( IOSLAVES_MINECRAFT_MASTER_TEMPAMP_DIR,'/',$worldname,".zip" );
					r = ::access(tempmap_path.c_str() , R_OK);
					sock->o_bool(r == 0);
					if (r == -1) {
						__log__ << LOG_ARROW_ERR << "Temporary map '" << $worldname << "' doesn't exist here" << std::flush;
						EXIT_FAILURE = EXIT_FAILURE_EXTERR;
						throw EXCEPT_ERROR_IGNORE;
					}
					sock->o_file(tempmap_path.c_str());
				} else {
					std::string mapfold = _S( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/maps/",$worldname );
					if (what != minecraft::transferWhat::SERVFOLD) {
						__log__ << NICE_WARNING << "master wants other than a perm save !" << std::flush;
						sock->o_bool(false);
						continue;
					}
					if (lastsavetime == 0) {
						__log__ << NICE_WARNING << "no save for world " << $worldname << " available !" << std::flush;
						sock->o_bool(false);
						continue;
					}
					if (ioslaves::infofile_get( _s(mapfold,"/truesave"), true) != "true") {
						__log__ << NICE_WARNING << "local save " << $worldname << " could be not the last save !" << std::flush;
						sock->o_bool(false);
						continue;
					}
					__log__ << "sending server folder save " << $worldname << std::flush;
					sock->o_bool(true);
					std::string map_path = _S( mapfold,'/',$worldname,'_',::ixtoa(lastsavetime,IX_HEX_MAJ),".zip" );
					sock->o_file(map_path.c_str());
				}
			} else {
				sock->o_bool(false);
				throw o;
			}
		} else if (o == ioslaves::answer_code::WANT_SEND) {
			if ($granmaster) 
				acceptFileSave(*sock, $server_name, $worldname, $slave_id, false);
			else {
				sock->i_int<int64_t>();
				sock->o_bool(false);
				__log__ << LOG_AROBASE_ERR << "Not granmaster : ignoring send request" << std::flush;
			}
		} else 
			throw o;
	}
	if ($start_is_perm and $granmaster) {
		std::string map_folder = _S( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/maps/",$worldname );
		r = ::mkdir(map_folder.c_str(), S_IRWXU|S_IRWXG);
		if (r == -1 and errno != EEXIST) {
			__log__ << LOG_AROBASE_ERR << "Can't create map folder '" << $worldname << "' : " << ::strerror(errno) << std::flush;
			throw EXCEPT_ERROR_IGNORE;
		}
		ioslaves::infofile_set(_s(IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/maps/",$worldname,"/truesave"), "false");
	}
	__log__ << LOG_AROBASE_OK << "End of requests, starting of server on port " << port << " can now start..." << std::flush;
	if ((o = (ioslaves::answer_code)sock->i_char()) != ioslaves::answer_code::OK) 
		throw o;
	__log__ << "Server thread is started" << std::flush;
	sock->set_read_timeout(TIMEOUT_JAVA_ALIVE);
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
	granmasterSlaveSet();
	ioslaves::answer_code o;
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::STOP_SERVER, {2,0}, false, true);
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
	sock.set_read_timeout(TIMEOUT_STOP_SERVER);
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) {
		if (o == ioslaves::answer_code::TIMEOUT) {
			__log__ << LOG_ARROW_ERR << "Java did not exit : " << COLOR_RED << "server seems to have crashed" << COLOR_RESET << ". Try to kill it." << std::flush;
			EXIT_FAILURE = EXIT_FAILURE_EXTERR;
			throw EXCEPT_ERROR_IGNORE;
		}
		throw o;
	}
	__log__ << LOG_ARROW_OK << "Thread and java exited" << std::flush;
	sock.set_read_timeout(TIMEOUT_COMM);
	while ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) {
		if (o == ioslaves::answer_code::WANT_REPORT)
			handleReportRequest(sock, $slave_id);
		else throw o;
	}
	if ($granmaster) 
		::setRunningOnSlave($server_name, "");
	__log__ << LOG_ARROW_OK << "Done ! Server is stopped" << std::flush;
}

/** ---------------------------- KILL ---------------------------- **/

void MServKill() {
	__log__ << LOG_ARROW << "Killing server..." << std::flush;
	granmasterSlaveSet();
	ioslaves::answer_code o;
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::KILL_SERVER, {2,0}, false, false);
	if ((o = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK)
		throw o;
	__log__ << LOG_ARROW_OK << "Kill order sent." << std::flush;
}

/** ---------------------------- CONSOLE ---------------------------- **/

void MServConsole () {
	__log__ << LOG_ARROW << "Connecting to LiveConsole™..." << std::flush;
	if ($locked) {
		::unlink(_s( IOSLAVES_MINECRAFT_MASTER_DIR,'/',$server_name,"/_mcmaster.lock" ));
		$locked = false;
	}
	granmasterSlaveSet();
	ioslaves::answer_code o;
	auto sock = getConnection($slave_id, $server_name, minecraft::op_code::COMM_SERVER, {6,0}, false, false);
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
	} catch (const std::exception& e) {
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

void MRefuse() {
	__log__ << LOG_ARROW << "Connecting to '" << $slave_id << "'..." << std::flush;
	socketxx::io::simple_socket<socketxx::base_netsock> sock = 
		iosl_master::slave_api_service_connect($slave_id, $master_id, "minecraft", TIMEOUT_CONNECT);
	sock.i_int<int64_t>();
	sock.i_int<uint16_t>();
	sock.o_bool(false);
	sock.o_str(std::string());
	__log__ << LOG_ARROW << "Toggling refuse option..." << std::flush;
	sock.o_char((char)minecraft::op_code::REFUSE_OPTION);
	sock.o_bool($refuse_servs);
	ioslaves::answer_code o;
	o = (ioslaves::answer_code)sock.i_char();
	if (o != ioslaves::answer_code::OK) 
		throw o;
}

void MPost (ioslaves::answer_code e) {
	if (e == EXCEPT_ERROR_IGNORE) throw EXCEPT_ERROR_IGNORE;
	if (e != ctx_postfnct_excpt_default) {
		switch (e) {
			case ioslaves::answer_code::OK: __log__ << COLOR_GREEN << "Success !" << COLOR_RESET << std::flush; return;
			case ioslaves::answer_code::MAY_HAVE_FAIL: __log__ << COLOR_YELLOW << "Operation may have failed !" << COLOR_RESET << std::flush; return;
			default: goto __error;
		}
	__error:
		const char* errstr = NULL;
		switch (e) {
			case ioslaves::answer_code::INTERNAL_ERROR: errstr = "Slave system or internal error !"; break;
			case ioslaves::answer_code::SECURITY_ERROR: errstr = "Security error !"; break;
			case ioslaves::answer_code::NOT_FOUND: errstr = "Not Found !"; break;
			case ioslaves::answer_code::BAD_STATE: errstr = "Operation inapplicable : bad state !"; break;
			case ioslaves::answer_code::BAD_TYPE: errstr = "Operation inapplicable : bad type !"; break;
			case ioslaves::answer_code::WANT_REPORT: errstr = "Slave wants to report something : can't handle request"; break;
			case ioslaves::answer_code::WANT_GET: errstr = "Slave wants to get something : can't handle request"; break;
			case ioslaves::answer_code::WANT_SEND: errstr = "Slave wants to tranfer something : can't handle request"; break;
			case ioslaves::answer_code::OP_NOT_DEF: errstr = "Operation not defined !"; break;
			case ioslaves::answer_code::EXISTS: errstr = "Already exists !"; break;
			case ioslaves::answer_code::UPNP_ERROR: errstr = "Port mapping error !"; break;
			case ioslaves::answer_code::DENY: errstr = "Slave refuses !"; break;
			case ioslaves::answer_code::INVALID_DATA: errstr = "Slave reports invalid data !"; break;
			case ioslaves::answer_code::LACK_RSRC: errstr = "Lacking ressources !"; break;
			case ioslaves::answer_code::EXTERNAL_ERROR: errstr = "Error outside the scope of ioslavesd-minecraft !"; break;
			case ioslaves::answer_code::TIMEOUT: errstr = "Timeout !"; break;
			case ioslaves::answer_code::NOT_AUTHORIZED: errstr = "Permission denied !"; break;
			default: case ioslaves::answer_code::ERROR: errstr = "Unknown error !";
		}
		__log__ << COLOR_RED << errstr << COLOR_RESET << std::flush;
		EXIT_FAILURE = EXIT_FAILURE_IOSL;
		throw EXCEPT_ERROR_IGNORE;
	}
}
