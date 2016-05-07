/**********************************************************\
 *                ioslaves : ioslaves-master
 *  Master program user interface for controlling ioslavesd
 * *********************************************************
 * Copyright © Félix Faisant 2013-2016. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common
#define IOSLAVES_MASTER_FINAL
#include "master.hpp"

	// Other
#include <memory>
#include <xifutils/polyvar.hpp>
#include <xifutils/cxx.hpp>
#include <xifutils/intstr.hpp>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <typeinfo>

	// Crypto
#include <openssl/md5.h>

	// Key storage plugins
#ifdef IOSLAVES_MASTER_KEYSTORE_EXT_METHODS
#include "keystore.hpp"
#include <dlfcn.h>
typedef void* dl_t;
#endif

	// Config
#define private public
#include <libconfig.h++>
#undef private

	// Files
#include <sys/stat.h>
#include <fcntl.h>

	// Network
#include <socket++/handler/socket_client.hpp>
#include <socket++/handler/socket_server.hpp>
#include <socket++/io/tunnel.hpp>
#include <socket++/base_unixsock.hpp>
#include <socket++/base_inet.hpp>
#include <socket++/quickdefs.h>

	// Log
#define IOSLAVES_LOG_DEFAULT_LOGSTREAM_IMPL
#include "log_defimpl.h"
pthread_mutex_t xlog::logstream_impl::mutex = PTHREAD_MUTEX_INITIALIZER;
std::ostringstream xlog::logstream_impl::stream;
bool _log_wait_flag = false;
void xlog::logstream_impl::log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid) noexcept {
	if (_log_wait_flag and not (m & LOG_ADD)) std::clog << std::endl;
	_log_wait_flag = false;
	switch (lvl) {
		case log_lvl::LOG: case log_lvl::_DEBUG: break;
		case log_lvl::NOTICE: case log_lvl::IMPORTANT: case log_lvl::MAJOR: std::clog << LOG_ARROW; break;
		case log_lvl::FATAL: case log_lvl::ERROR: case log_lvl::OOPS: case log_lvl::SEVERE: std::clog << LOG_ARROW_ERR << COLOR_RED << "Error : " << COLOR_RESET; break;
		case log_lvl::WARNING: std::clog << COLOR_YELLOW << "Warning : " << COLOR_RESET; break;
		case log_lvl::DONE: std::clog << LOG_ARROW_OK; break;
	}
	std::clog << msg;
	if (m & LOG_WAIT) { _log_wait_flag = true; std::clog << ' '; } 
	else std::clog << std::endl;
}

	// Exit
int _exit_failure_code = 29;
#undef EXIT_FAILURE
#define EXIT_FAILURE _exit_failure_code

	// ioslaves' variables
std::string $master_id;
std::string $slave_id;
bool $addr_defined = false;
socketxx::base_netsock::addr_info $connect_addr = {in_addr{0},0};
bool $port_open;
in_port_t $port, $port_end = 0;
bool $port_tcp;
std::string $port_descr;
bool $shutd_reboot;
std::string $service_name;
iosl_master::on_type $poweron_type = iosl_master::on_type::_AUTO;
std::string $on_mac;
std::string $on_gateway;
std::string $new_key_file_path;
std::string $api_co_unix_sock_path;
bool $auth = false;
bool $auto_auth = true;
timeval $connect_timeout = {1,000000};
timeval $comm_timeout = {4,000000};
timeval $op_timeout = {60,000000};
bool $ignore_net_errors = false;
time_t $log_begin, $log_end;
int16_t $autoshutdown = -1;
std::string $key_sl_auth_footprint;
std::string $key_sl_auth_ip;
const char* $key_sl_auth_perms_file_path = NULL;
std::string $key_sl_master;
std::string $key_storage_method = "raw";

// ioslaves' core functionnality functions
	void IPreSlaveCo ();
		void IPreService ();
			void IServStart ();
			void IServStop ();
			void IApi ();
		void IPostService (ioslaves::answer_code);
		void IPort ();
		void IShutd ();
		void IStat ();
		void ILog ();
		void ISlKeyAuth ();
		void ISlKeyDel ();
	void IPostSlaveCo (ioslaves::answer_code);
	void IKeygen ();
	void IPowerup ();
	void IioslFile2JSON ();
void IPost (ioslaves::answer_code);

	// Commmand line arguments
#define OPTCTX_IMPL

#define OPTCTX_POSTFNCT_EXCEPT_T ioslaves::answer_code
#define OPTCTX_POSTFNCT_EXCEPT_DEFAULT (ioslaves::answer_code)0
#define EXCEPT_ERROR_IGNORE (ioslaves::answer_code)1

#define OPTCTX_CTXS                              slctrl                         , slctrl_Ser                     , slctrl_Sstart    , slctrl_Sstop    , slctrl_Sapi       , slctrl_port , slctrl_shutd , slctrl_stat , slctrl_log , slctrl_authk     , slctrl_delk     , keygen        , powerup        , tojson
#define OPTCTX_PARENTS                           ROOT                           , slctrl                         , slctrl_Ser       , slctrl_Ser      , slctrl_Ser        , slctrl      , slctrl       , slctrl      , slctrl     , slctrl           , slctrl          , ROOT          , ROOT           , ROOT
#define OPTCTX_PARENTS_NAMES  "action"         , "slave command"                , "service operation"            , NULL             , NULL            , NULL              , NULL        , NULL         , NULL        , NULL       , NULL             , NULL            , NULL          , NULL           , NULL
#define OPTCTX_PARENTS_FNCTS  CTXFP(NULL,IPost), CTXFP(IPreSlaveCo,IPostSlaveCo), CTXFP(IPreService,IPostService), CTXFO(IServStart), CTXFO(IServStop), CTXFO(IApi)       , CTXFO(IPort), CTXFO(IShutd), CTXFO(IStat), CTXFO(ILog), CTXFO(ISlKeyAuth), CTXFO(ISlKeyDel), CTXFO(IKeygen), CTXFO(IPowerup), CTXFO(IioslFile2JSON)
#define OPTCTX_NAMES                             "--control"                    , "--service"                    , "--start"        , "--stop"        , "--api-service-co", "--xxx-port", "--shutdown" , "--status"  , "--log"    , "--auth-key"     , "--revoke-key"  , "--add-key"   , "--on"         , "--to-json"

#define OPTCTX_PROG_NAME "ioslaves-master"
#include <xifutils/optctx.hpp>

inline void try_parse_IDs (int argc, char* const argv[]) {
	if (not $master_id.empty()) return;
	if (argc == optind || argv[optind][0] == '-') 
		return;
	$master_id = argv[optind++];
	if (!ioslaves::validateMasterID($master_id)) 
		try_help("ioslaves-master: invalid master ID\n");
	if (argc == optind || argv[optind][0] == '-') 
		try_help("ioslaves-master: excepted slave ID after master ID\n");
	$slave_id = argv[optind++];
	if (!ioslaves::validateSlaveName($slave_id)) 
		try_help("ioslaves-master: invalid slave ID\n");
}
inline void test_for_IDs () {
	if ($master_id.empty())
		try_help("ioslaves-master: master and slave IDs requiered\n");
}

int main (int argc, char* const argv[]) {
	int r;
	
	struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"addr", required_argument, NULL, 'd'},
		{"no-interactive", no_argument, NULL, 'i'},
		{"control", no_argument, NULL, 'C'},
			{"auth", required_argument, NULL, 'f'},
			{"port", required_argument, NULL, 'p'},
			{"service", required_argument, NULL, 'S'},
				{"start", no_argument, NULL, 's'},
				{"stop", no_argument, NULL, 'o'},
				{"api-service-co", required_argument, NULL, 'a'},
			{"open-port", required_argument, NULL, 'P'},
			{"close-port", required_argument, NULL, 'X'},
			{"reboot", no_argument, NULL, 'R'},
			{"shutdown", optional_argument, NULL, 'D'},
			{"status", no_argument, NULL, 'G'},
			{"log", optional_argument, NULL, 'L'},
			{"auth-key", no_argument, NULL, 'k'},
			{"revoke-key", required_argument, NULL, 'r'},
		{"keygen", required_argument, NULL, 'K'},
		{"on", optional_argument, NULL, 'O'},
		{"to-json", no_argument, NULL, 'J'},
		{NULL, 0, NULL, 0}
	};
	
	{ int r;
		r = ::access(IOSLAVES_MASTER_DIR, F_OK);
		if (r == -1) {
			r = ::mkdir(IOSLAVES_MASTER_DIR, 0740);
			if (r == -1) {
				std::cerr << COLOR_RED << "Can't create ioslaves-master directory" << COLOR_RESET << " (" << IOSLAVES_MASTER_DIR << ") : " << ::strerror(errno) << std::endl;
				return EXIT_FAILURE;
			}
		}
	}
	
	try_parse_IDs(argc, argv);
	
	int opt, opt_charind = 0;
	while ((opt = ::getopt_long(argc, argv, "-hid:Cf:S:soa:P:X:RDGL::kr:K:O::J", long_options, &opt_charind)) != -1) {
		switch (opt) {
			case 'h':
				::puts("ioslaves-master | ioslaves control program for network masters\n"
				       "Usage: ioslaves-master MASTER-ID SLAVE-ID [--addr=ADDR] --ACTION [--COMMAND [OPTIONS] ...]\n"
				       "\n"
				       "General options :\n"
				       "      MASTER-ID             The master ID, used for authentication and logging.\n"
				       "      SLAVE-ID              If only the slave ID is used, IP and port are automatically retrieved.\n"
				       "  -d, --addr=(HOST|IP)[:PORT] Explicit address : can be an IP or an hostname, with optional :PORT\n"
				       "  -i, --no-interactive      Disable prompting. Log in HTML.\n"
				       "\n"
				       "Actions :\n"
				       "  -C, --control             Connect to distant ioslaves server. Authentication is optional but\n"
				       "                             needed for most operations.\n"
				       "      Options :\n"
				       "        -f, --auth=(yes|auto|no)  Force authentication or not.\n"
				       "      Commands :\n"
				       "        -S, --service=SERVICE   Control services on the slave\n"
				       "            Operations :\n"
				       "               -s, --start          Start service\n"
				       "               -o, --stop           Stop service\n"
				       "               -a, --api-service-co=UNIX_SOCK\n"
				       "                                    Get connection to an ioslaves API service. Here, ioslaves only\n"
				       "                                     relays between the distant API service and a progam that knows\n"
				       "                                     the protocol of the service, via an unix socket.\n"
				       "        -P, --open-port=(T|U)PORT[-END] [DESCR]\n"
				       "                                    Open port(s) (TCP/UDP) on the gatway of the distant slave via UPnP.\n"
				       "        -X, --close-port=(T|U)PORT[-END]\n"
				       "                                    Close opened port(s) on the distant gateway.\n"
				       "        -R, --reboot                Reboot distant slave.\n"
				       "        -D, --shutdown [AUTO_TIME]  Shutdown distant slave. AUTO_TIME param manages automatic\n"
				       "                                     shutdown. If AUTO_TIME=0, inhibits auto-shutdown. If AUTO_TIME>0,\n"
				       "                                     sets the automatic shutdown in AUTO_TIME minutes.\n"
				       "        -G, --status                Report overview status of the slave as JSON.\n"
				       "        -L, --log [BEGIN[-END]]      Get slave log lines from timestamps BEGIN to END\n"
				       "                                     (0 for no limit). Returns JSON if not interactive.\n"
				       "        -k, --auth-key MASTER FOOTPRINT PERMFILE [IP]   Authorize a master for 4 seconds to send it's\n"
				       "                                     new key with known footprint, which should be transfered with\n"
				       "                                     integrity guaranty. Master IP verification is optional. Models of\n"
				       "                                     perms files can be found in " IOSLAVES_MASTER_KEYS_MODELS_DIR "\n"
				       "        -r, --revoke-key=MASTER     Delete key of given master.\n"
				       "  -K, --keygen METHOD      Generate (and replace if exists) a key for the slave. The key can be copied\n"
				       "                            on the slave manually or automatically with the authorization of a master.\n"
				       "                            If the storage METHOD is 'raw', the key is stored in clear in the key file.\n"
				       "                            Else, a key storage plugin will be loaded as METHOD.ioslmcext to store the key.\n"
				       "  -O, --on [METHOD ARG[s]] Power on slave using several methods :\n"
				       "                            MAGIC_PKT: wake up the slave using a magic packet containing the\n"
				       "                                        MAC address of its compatible NIC (UDP packet on port 9).\n"
				       "                                       If the 2nd arg is defined, the packet is sent on represented\n"
				       "                                        hostname instead of the broadcast addr of the local network.\n"
				       "                                       If sent to the WAN, the router must support it.\n"
				       "                            GATEWAY: tell the 'wake-gateway' ioslavesd plugin of a slave on the same\n"
				       "                                      network to relay the start request (WoL, another relay...).\n"
				       "                                      Used if magic packets cannot traverse the NAT, or for\n"
				       "                                      hierarchical organizations. Takes the name or address of the gateway.\n"
				       "  -J, --to-json            Convert slave info file ~/ioslaves-master/slaves/[slave].conf into JSON.\n"
				       "\n");
				return EXIT_SUCCESS;
			case 'i':
				optctx::interactive = false;
				try_parse_IDs(argc, argv);
				break;
			case 'd': {
				try {
					$connect_addr = socketxx::base_netsock::addr_info ( IOSLAVES_MASTER_DEFAULT_PORT, optarg );
				} catch (const socketxx::bad_addr_error& e) {
					try_help("ioslaves-master: invalid slave address\n");
				} catch (const socketxx::dns_resolve_error& e) {
					std::cerr << COLOR_RED << "Can't resolve slave hostname '" << e.failed_hostname << "' !" << COLOR_RESET << std::endl;
					return EXIT_FAILURE_CONN;
				}
				$addr_defined = true;
			} break;
			case 'C':
				optctx::optctx_set(optctx::slctrl);
				test_for_IDs();
				break;
			case 'f':
				optctx::optctx_test("--auth", optctx::slctrl);
				     if (_S(optarg) == "yes")  { $auto_auth = false; $auth = true; }
				else if (_S(optarg) == "auto") { $auto_auth = true; }
				else if (_S(optarg) == "no")   { $auto_auth = false; $auth = false; }
				else 
					try_help("--auth mode must be 'yes', 'no', or 'auto'\n");
				break;
			case 'S':
				optctx::optctx_set(optctx::slctrl_Ser);
				if ($auto_auth) $auth = true;
				$service_name = optarg;
				if (!ioslaves::validateServiceName($service_name)) 
					try_help("--service: invalid service ID\n");
				break;
			case 's':
				optctx::optctx_set(optctx::slctrl_Sstart);
				break;
			case 'o':
				optctx::optctx_set(optctx::slctrl_Sstop);
				break;
			case 'a': 
				optctx::optctx_set(optctx::slctrl_Sapi);
				$api_co_unix_sock_path = optarg;
				break;
			case 'P':
				optctx::optctx_optnm[optctx::slctrl_port] = "--open-port";
				optctx::optctx_set(optctx::slctrl_port);
				$port_open = true;
			__port_section: {
				if ($auto_auth) $auth = true;
				std::string port_str = optarg;
				if (port_str.size() < 2 or (port_str[0] != 'T' and port_str[0] != 'U')) 
					try_help(_s(optctx::optctx_optnm[optctx::slctrl_port]," : Protocol letter must be 'T' for TCP or 'U' for UDP, followed by a port number.\n"));
				if (port_str[0] == 'T') $port_tcp = true;
				else $port_tcp = false;
				size_t dash_pos = port_str.find_first_of('-');
				if (dash_pos != std::string::npos) {
					std::string beg = port_str.substr(1, dash_pos-1);
					std::string end = port_str.substr(dash_pos+1);
					if (beg.length() < 1 or beg.length() > 5 or end.length() < 1 or end.length() > 5)
						try_help(_s(optctx::optctx_optnm[optctx::slctrl_port]," : Port number invalid\n"));
					try {
						long beg_num = ::atoix<long>(beg, IX_DEC), end_num = ::atoix<long>(end, IX_DEC);
						if (end_num < 1 or end_num > 65535 or beg_num < 1 or beg_num > 65535) throw NULL;
						if (beg_num > end_num) 
							try_help(_s(optctx::optctx_optnm[optctx::slctrl_port]," : Port range : End port number must be greater than begin\n"));
						$port = (uint16_t)beg_num;
						$port_end = (uint16_t)end_num;
					} catch (...) {
						try_help(_s(optctx::optctx_optnm[optctx::slctrl_port]," : Port number must be a number between 1 and 65535.\n"));
					}
				} else {
					std::string str = port_str.substr(1);
					if (str.length() < 1 or str.length() > 5)
						try_help(_s(optctx::optctx_optnm[optctx::slctrl_port]," : Port number invalid\n"));
					try {
						long port_num = ::atoix<long>(str, IX_DEC);
						if (port_num < 1 or port_num > 65535) throw NULL;
						$port = (uint16_t)port_num;
					} catch (...) {
						try_help(_s(optctx::optctx_optnm[optctx::slctrl_port]," : Port number must be a number between 1 and 65535.\n"));
					}
				}
				if ($port_open)
					if (optind != argc and argv[optind][0] != '-')
						$port_descr = argv[optind++];
			} break;
			case 'X':
				optctx::optctx_optnm[optctx::slctrl_port] = "--close-port";
				optctx::optctx_set(optctx::slctrl_port);
				$port_open = false;
				goto __port_section;
				break;
			case 'R':
				optctx::optctx_optnm[optctx::slctrl_shutd] = "--reboot";
				optctx::optctx_set(optctx::slctrl_shutd);
				$shutd_reboot = true;
				if ($auto_auth) $auth = true;
				break;
			case 'D':
				optctx::optctx_set(optctx::slctrl_shutd);
				if (optarg != NULL) {
					try {
						$autoshutdown = ::atoix<uint16_t>(optarg);
					} catch (...) {
						try_help("--shutdown: invalid automatic shutdown delay");
					}	
				} else $autoshutdown = -1;
				if ($auto_auth) $auth = true;
				break;
			case 'G':
				optctx::optctx_set(optctx::slctrl_stat);
				if ($auto_auth) $auth = false;
				break;
			case 'L': {
				optctx::optctx_set(optctx::slctrl_log);
				if ($auto_auth) $auth = true;
				$log_begin = 0;
				$log_end = 0;
				if (optarg != NULL) {
					std::string timestamps = optarg;
					size_t pos;
					try {
						if ((pos = timestamps.find_first_of('-')) != std::string::npos) {
							$log_begin = ::atoix<time_t>(timestamps.substr(0,pos));
							$log_end = ::atoix<time_t>(timestamps.substr(pos+1));
						} else {
							$log_begin = ::atoix<time_t>(timestamps);
						}
					} catch (...) {
						try_help("--log: invalid timestamps\n");
					}
				}
			} break;
			case 'k': {
				optctx::optctx_set(optctx::slctrl_authk);
				if ($auto_auth) $auth = true;
				if (optind == argc or argv[optind][0] == '-') 
					try_help("--auth-key must take key sender master id as first argument\n");
				$key_sl_master = argv[optind++];
				if (not ioslaves::validateMasterID($key_sl_master)) 
					try_help("--auth-key: invalid master id\n");
				if (optind == argc or argv[optind][0] == '-') 
					try_help("--auth-key must take key footprint as second argument\n");
				std::string footprint = argv[optind++];
				if (not ioslaves::validateHexa(footprint) or footprint.length() != 32) 
					try_help("--auth-key: invalid key footprint\n");
				std::transform(footprint.begin(), footprint.end(), std::back_inserter($key_sl_auth_footprint), ::tolower);
				if (optind == argc or argv[optind][0] == '-') 
					try_help("--auth-key must take key permissions settings file as third argument\n");
				$key_sl_auth_perms_file_path = argv[optind++];
				r = ::access($key_sl_auth_perms_file_path, R_OK);
				if (r == -1) 
					try_help("--auth-key: unable to access to key permissions settings file\n");
				if (optind == argc or argv[optind][0] == '-') 
					break;
				$key_sl_auth_ip = argv[optind++];
				in_addr_t auth_ip;
				r = ::inet_pton(AF_INET, $key_sl_auth_ip.c_str(), &auth_ip);
				if (r != 1) 
					try_help("--auth-key: invalid key sender master IP\n");
			} break;
			case 'r': {
				optctx::optctx_set(optctx::slctrl_delk);
				if ($auto_auth) $auth = true;
				$key_sl_master = optarg;
				if (not ioslaves::validateMasterID($key_sl_master)) 
					try_help("--revoke-key: invalid master ID\n");
			} break;
			case 'K': {
				optctx::optctx_set(optctx::keygen);
				$key_storage_method = optarg;
				if (not ioslaves::validateName($key_storage_method)) 
					try_help("--keygen METHOD : invalid method name\n");
				test_for_IDs();
			} break;
			case 'O': {
				optctx::optctx_set(optctx::powerup);
				test_for_IDs();
				std::string on_str_type = (optarg != NULL) ? optarg : std::string();
				if (on_str_type == "MAGIC_PKT") {
					$poweron_type = iosl_master::on_type::WoL;
					if (optind == argc or argv[optind][0] == '-') 
						try_help("--on=MAGIC_PKT must take MAC addr as argument\n");
					$on_mac = argv[optind++];
					if (optind != argc and argv[optind][0] != '-') {
						$poweron_type = iosl_master::on_type::WoW;
						try {
							$connect_addr = socketxx::base_netsock::addr_info( 9, argv[optind++] );
						} catch (const socketxx::bad_addr_error) {
							try_help("--on=MAGIC_PKT : second arg must be a valid IP addr or hostname\n");
						} catch (const socketxx::dns_resolve_error& e) {
							std::cerr << COLOR_RED << "Can't resolve slave hostname '" << e.failed_hostname << "' !" << COLOR_RESET << std::endl;
							return EXIT_FAILURE_CONN;
						}
					}
				} 
				else if (on_str_type == "GATEWAY") {
					$poweron_type = iosl_master::on_type::GATEWAY;
					if (optind == argc or argv[optind][0] == '-') 
						try_help("--on=GATEWAY must take the name of the gateway as argument\n");
					$on_gateway = argv[optind++];
					if (not ioslaves::validateSlaveName($on_gateway))
						try_help("--on=GATEWAY : invalid gateway name\n"); 
				} 
				else if (not on_str_type.empty()) {
					try_help("--on : invalid mode\n");
				}
			} break;
			case 'J':
				optctx::optctx_set(optctx::tojson);
				break;
			default: 
				try_help();
		}
	}
	optctx::optctx_end();
	
	/// Execute
	try {
		optctx::optctx_exec();
	} catch (const socketxx::error& se) {
		if ($ignore_net_errors) return EXIT_SUCCESS;
		std::cerr << COLOR_RED << "network error : " << COLOR_RESET << se.what() << std::endl;
		return EXIT_FAILURE_COMM;
	} catch (const master_err& e) {
		std::cerr << COLOR_RED << "master error : " << COLOR_RESET << e.what() << std::endl;
		return e.ret;
	} catch (const std::exception& e) {
		std::cerr << "Exception of type '" << typeid(e).name() << "' catched : " << COLOR_RED << e.what() << COLOR_RESET << std::endl;
		return EXIT_FAILURE;
	} catch (const ioslaves::answer_code) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/********************************************************************************************************************/


	///---- Connection to slave ----///

socketxx::simple_socket_client<socketxx::base_netsock>* $slave_sock = NULL;

void IPreSlaveCo () {
		// Hostname or IP
	try {
		if (not $addr_defined) {
			in_port_t $connect_port = IOSLAVES_MASTER_DEFAULT_PORT;
			try { // Retriving port number with SRV records
				std::cerr << "Retriving port number from SRV record _ioslavesd._tcp." << $slave_id << '.' << XIFNET_SLAVES_DOM << "..." << std::endl;
				$connect_port = iosl_master::slave_get_port_dns($slave_id);
			} catch (const iosl_master::ldns_error& e) {
				std::cerr << (optctx::interactive?COLOR_YELLOW:COLOR_RED) << "Failed to retrive port number : " << e.what();
				if (optctx::interactive) 
					std::cerr << " - using port " << $connect_port << COLOR_RESET << std::endl;
				else { 
					std::cerr << COLOR_RESET << std::endl;
					EXIT_FAILURE = EXIT_FAILURE_CONN; throw EXCEPT_ERROR_IGNORE;
				}
			}
			$connect_addr = socketxx::base_netsock::addr_info ( _s($slave_id,'.',XIFNET_SLAVES_DOM), $connect_port );
		}
	} catch (const socketxx::dns_resolve_error& e) {
		std::cerr << COLOR_RED << "Can't resolve hostname '" << e.failed_hostname << "' !" << COLOR_RESET << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_CONN; throw EXCEPT_ERROR_IGNORE;
	}
		// Connecting
	try {
		std::cerr << "Connecting to " << $slave_id << " at " << $connect_addr.get_ip_str() << ":" << $connect_addr.get_port() << "..." << std::endl;
		$slave_sock = new socketxx::simple_socket_client<socketxx::base_netsock> ($connect_addr, $connect_timeout);
		$slave_sock->set_read_timeout($comm_timeout);
	} catch (const socketxx::end::client_connect_error& e) {
		std::cerr << COLOR_RED << "Failed to connect to slave : " << COLOR_RESET << e.what() << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_DOWN;
		delete $slave_sock;
		throw EXCEPT_ERROR_IGNORE;
	}
	try {
		$slave_sock->o_bool(true);
			// Authentication
		$slave_sock->o_str($master_id);
		$slave_sock->o_bool($auth);
		if ($auth) {
			std::cerr << "Authentication..." << std::endl;
			iosl_master::authenticate(*$slave_sock, _S($master_id,'.',$slave_id));
		}
		$slave_sock->set_read_timeout($op_timeout);
	} catch (const socketxx::error& e) {
		std::cerr << COLOR_RED << "Failed to communicate with " << $slave_id << " : " << COLOR_RESET << e.what() << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_COMM;
		delete $slave_sock;
		throw EXCEPT_ERROR_IGNORE;
	}
}

void IPostSlaveCo (ioslaves::answer_code e) {
	if (e == ctx_postfnct_excpt_default and $slave_sock != NULL) {
		ioslaves::answer_code answ = (ioslaves::answer_code)$slave_sock->i_char();
		delete $slave_sock;
		if (answ != ioslaves::answer_code::OK) 
			throw answ;
	} else {
		if ($slave_sock != NULL)
			delete $slave_sock;	// Disconnect
		throw e;
	}
}

	///---- Service managing ----///

void IPreService () {
	std::cerr << "Managing service '" << $service_name << "'" << std::endl;
}

void IServStart () {
	std::cerr << "Starting service..." << std::endl;
	$slave_sock->o_char((char)ioslaves::op_code::SERVICE_START);
	$slave_sock->o_str($service_name);
}

void IServStop () {
	std::cerr << "Stopping service..." << std::endl;
	$slave_sock->o_char((char)ioslaves::op_code::SERVICE_STOP);
	$slave_sock->o_str($service_name);
}

void IPostService (ioslaves::answer_code e) {
	if (e == EXCEPT_ERROR_IGNORE) throw EXCEPT_ERROR_IGNORE;
	ioslaves::answer_code answ;
	if (e == ctx_postfnct_excpt_default) 
		answ = (ioslaves::answer_code)$slave_sock->i_char();
	else answ = e;
	EXIT_FAILURE = EXIT_FAILURE_IOSL;
	switch (answ) {
		case ioslaves::answer_code::BAD_TYPE: std::cerr << COLOR_RED << "Operation inapplicable : bad service type" << COLOR_RESET << std::endl; break;
		case ioslaves::answer_code::BAD_STATE: std::cerr << COLOR_RED << "Operation inapplicable : bad service state" << COLOR_RESET << std::endl; break;
		case ioslaves::answer_code::NOT_FOUND: std::cerr << COLOR_RED << "Service not found" << COLOR_RESET << std::endl; break;
		case ioslaves::answer_code::EXTERNAL_ERROR: std::cerr << COLOR_RED << "Failed to operate on this service !" << COLOR_RESET << std::endl; break;
		default: throw answ;
	}
	throw EXCEPT_ERROR_IGNORE;
}

	///---- API services ----///

void IApi () {
	std::cerr << "Connecting to API service..." << std::endl;
	$slave_sock->o_char((char)ioslaves::op_code::CALL_API_SERVICE);
	$slave_sock->o_str($service_name);
	try {
		IPostService(ctx_postfnct_excpt_default);
	} catch (const ioslaves::answer_code& e) {
		if (e != ioslaves::answer_code::OK) 
			throw e;
	}
	EXIT_FAILURE = EXIT_FAILURE_COMM;
	bool servmode = false;
	int r;
	std::cerr << "Communication UNIX socket : " << $api_co_unix_sock_path << std::endl;
	const char* sockpath = $api_co_unix_sock_path.c_str();
	struct stat sockstat;
	r = ::stat(sockpath, &sockstat);
	if (r == -1) {
		if (errno == ENOENT) servmode = true;
		else throw xif::sys_error("stat(UNIX_SOCK_PATH) failed");
	} else {
		if (not S_ISSOCK(sockstat.st_mode))
			throw xif::sys_error("UNIX_SOCK_PATH: not a socket");
	}
	socketxx::base_unixsock* cli = NULL;
	if (servmode) {
		socketxx::simple_socket_server<socketxx::base_unixsock,void> serv(socketxx::base_unixsock::addr_info($api_co_unix_sock_path.c_str()), 1);
		cli = new socketxx::base_unixsock( serv.wait_new_client() );
	} else {
		socketxx::simple_socket_client<socketxx::base_unixsock> client($api_co_unix_sock_path.c_str());
		cli = new socketxx::base_unixsock( client );
	}
	std::cerr << "Letting flow the Data !" << std::endl;
	std::auto_ptr< socketxx::base_unixsock > _auto_cli(cli);
	socketxx::io::tunnel<socketxx::base_netsock, socketxx::base_unixsock> tunnel (*$slave_sock);
	tunnel.start_tunneling(*cli, NULL);
	delete $slave_sock;
	::exit(EXIT_SUCCESS);
}

	///---- Port opening/closing ----///

void IPort () {
	if ($port_open) {
		if ($port_end != 0) std::cerr << "Opening ports " << $port << " to " << $port_end << " on distant slave's gateway..." << std::endl;
		else std::cerr << "Opening port " << $port << " on distant slave's gateway..." << std::endl;
		$slave_sock->o_char((char)ioslaves::op_code::IGD_PORT_OPEN);
		if ($port_descr.empty()) $port_descr = "ioslaves";
		$slave_sock->o_str($port_descr);
	} else {
		std::cerr << "Closing port(s) on distant slave's gateway..." << std::endl;
		$slave_sock->o_char((char)ioslaves::op_code::IGD_PORT_CLOSE);
	}
	if ($port_end != 0) $slave_sock->o_char($port_tcp?'T':'U');
	else                $slave_sock->o_char($port_tcp?'t':'u');
	$slave_sock->o_int<uint16_t>($port);
	if ($port_end != 0) $slave_sock->o_int<uint16_t>($port_end);
	ioslaves::answer_code answ = (ioslaves::answer_code)$slave_sock->i_char();
	EXIT_FAILURE = EXIT_FAILURE_IOSL;
	switch (answ) {
		case ioslaves::answer_code::MAY_HAVE_FAIL: std::cerr << COLOR_YELLOW << "UPnP Operation may have failed, but on some gateways it's OK" << COLOR_RESET << std::endl; return;
		case ioslaves::answer_code::ERROR: std::cerr << COLOR_RED << "UPnP error !" << COLOR_RESET << std::endl; break;
		default: throw answ;
	}
	throw EXCEPT_ERROR_IGNORE;
}

	///---- Start/Shutdown/Sleep/Status... ----///

void IShutd () {
	if ($autoshutdown == -1) {
		std::cerr << "Trying to shut down distant slave..." << std::endl;
		if ($shutd_reboot)
			$slave_sock->o_char((char)ioslaves::op_code::SLAVE_REBOOT);
		else
			$slave_sock->o_char((char)ioslaves::op_code::SLAVE_SHUTDOWN);
		$ignore_net_errors = true;
	} else {
		if ($autoshutdown == 0) std::cerr << "Disabling auto-shutdown..." << std::endl;
		else std::cerr << "Set shutdown time in " << $autoshutdown << "min..." << std::endl;
		$slave_sock->o_char((char)ioslaves::op_code::SHUTDOWN_CTRL);
		$slave_sock->o_int<uint32_t>($autoshutdown*60);
	}
}

void IStat () {
	std::cerr << "Getting slave status and infos..." << std::endl;
	$slave_sock->o_char((char)ioslaves::op_code::GET_STATUS);
	xif::polyvar info = $slave_sock->i_var();
	if ($slave_id != (std::string)info["me"]) {
		std::cerr << LOG_ARROW_ERR << "Received status info of slave '" << (std::string)info["me"] << "', not slave '" << $slave_id << "' !" << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_IOSL;
		throw EXCEPT_ERROR_IGNORE;
	}
	std::cout << info.to_json(3) << std::endl;
}

const char* log_lvl_strs[] = { "FATAL", "ERROR", "OOPS", "SEVERE", "WARNING", "NOTICE", "LOG", "IMP", "MAJOR", "DONE" };
void ILog () {
	std::cerr << "Getting log lines from " << $log_begin << " to " << $log_end << "..." << std::endl;
	$slave_sock->o_char((char)ioslaves::op_code::LOG_HISTORY);
	$slave_sock->o_int<uint64_t>($log_begin);
	$slave_sock->o_int<uint64_t>($log_end);
	size_t lines = $slave_sock->i_int<uint64_t>();
	if (not optctx::interactive) std::cout << "[";
	while (lines --> 0) {
		time_t l_time = $slave_sock->i_int<uint64_t>();
		ushort l_lvln = $slave_sock->i_char();
		const char* l_lvlstr = (l_lvln >= sizeof(log_lvl_strs)/sizeof(const char*)) ? "???" : log_lvl_strs[l_lvln];
		std::string l_part = $slave_sock->i_str();
		std::string l_msg = $slave_sock->i_str();
		if (optctx::interactive) {
			tm gmt_time;
			::gmtime_r(&l_time, &gmt_time);
			char time_str[30];
			::strftime(time_str, sizeof(time_str), "%F %TZ ", &gmt_time);
			std::cout << time_str;
			if (not l_part.empty()) std::cout << "[" << l_part << "] ";
			std::cout << "[" << l_lvlstr << "] ";
			std::cout << l_msg << std::endl;
		} else {
			std::cout << xif::polyvar(xif::polyvar::map({
				{"t",l_time}, {"lvl",l_lvlstr}, {"part",(l_part.empty()?xif::polyvar():xif::polyvar(l_part))}, {"msg",l_msg}
			})).to_json();
			if (lines != 0) std::cout << ',';
		}
	}
	if (not optctx::interactive) std::cout << "]" << std::endl;
}

void IPowerup () {
	try {
	if ($poweron_type == iosl_master::on_type::_AUTO) {
		bool up = iosl_master::slave_test($slave_id);
		if (up) {
			std::cerr << COLOR_YELLOW << "Slave '" << $slave_id << "' is already up !" << COLOR_RESET << std::endl;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		}
		time_t delay;
		try {
			delay = iosl_master::slave_start($slave_id, $master_id);
		} catch (const std::exception& e) {
			std::cerr << COLOR_RED << "Power up error" << COLOR_RESET << " : " << e.what() << std::endl;
			EXIT_FAILURE = EXIT_FAILURE_EXTERR;
			throw EXCEPT_ERROR_IGNORE;
		}
		if (optctx::interactive) {
			std::cout << "Will be up in... " << std::flush;
			std::string timestr;
			do {
				timestr = ::ixtoa(delay);
				std::cout << timestr << std::flush;
				::sleep(1);
				std::cout << std::string(timestr.length(), '\b') << "\033[K" << std::flush;
			} while (--delay > 0);
			std::cout << std::endl << "Verifying... " << std::flush;
			bool up = iosl_master::slave_test($slave_id);
			if (up) std::cout << COLOR_GREEN << "Up !" << COLOR_RESET << std::endl;
			else {
				std::cout << COLOR_RED << "Seems to be still down :(" << COLOR_RESET << std::endl;
				EXIT_FAILURE = EXIT_FAILURE_EXTERR;
				throw EXCEPT_ERROR_IGNORE;
			}
		} else {
			std::cout << ::ixtoa(delay) << std::endl;
		}
	} else {
		if ($poweron_type == iosl_master::on_type::WoW) {
			std::cout << "Sending magic packet for " << $on_mac << " to " << $connect_addr.get_ip_str() << ":" << $connect_addr.get_port() << std::endl;
			ioslaves::wol::magic_send($on_mac.c_str(), true, $connect_addr.get_ip_addr().s_addr, $connect_addr.get_port());
		} else if ($poweron_type == iosl_master::on_type::WoL) {
			std::cout << "Broadcasting magic packet for " << $on_mac << " on local network..." << std::endl;
			ioslaves::wol::magic_send($on_mac.c_str(), false);
		} else if ($poweron_type == iosl_master::on_type::GATEWAY) {
			std::cout << "Relaying start request of slave '" << $slave_id << "' via gateway '" << $on_gateway << "'..." << std::endl;
			socketxx::io::simple_socket<socketxx::base_netsock> sock = iosl_master::slave_api_service_connect($on_gateway, $master_id, "wake-gateway");
			sock.o_str($slave_id);
			ioslaves::answer_code o = (ioslaves::answer_code)sock.i_char();
			if (o != ioslaves::answer_code::OK) {
				std::cerr << COLOR_RED << "Wake-gateway service failed to start slave" << COLOR_RESET << " (" << ioslaves::getAnswerCodeDescription(o) << ")" << std::endl;
				EXIT_FAILURE = EXIT_FAILURE_IOSL;
				throw EXCEPT_ERROR_IGNORE;	
			}
			time_t dist_delay = sock.i_int<uint16_t>();
			std::cout << "Announced delay : " << dist_delay << std::endl;
		}
		std::cout << COLOR_GREEN << "Done." << COLOR_RESET << std::endl;
	}
	} catch (const std::exception& e) {
		std::cerr << COLOR_RED << "Power up error" << COLOR_RESET << " : " << e.what() << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_EXTERR;
		throw EXCEPT_ERROR_IGNORE;
	}
}

	///---- Keys ----///

void IKeygen () {
	std::cerr << LOG_ARROW << "Generating key for slave '" << $slave_id << "'..." << std::endl;
	unsigned char* keybuf = ioslaves::generate_random(KEY_LEN);
	RAII_AT_END({ delete[] keybuf; });
	ioslaves::key_t key;
	::memcpy(key.bin, keybuf, KEY_LEN);
	int r;
	r = ::access(IOSLAVES_MASTER_KEYS_DIR, F_OK);
	if (r == -1) {
		r = ::mkdir(IOSLAVES_MASTER_KEYS_DIR, 0700);
		if (r == -1) throw xif::sys_error("can't create keys dir");
	}
	std::string key_path = _S( IOSLAVES_MASTER_KEYS_DIR,"/",$master_id,'.',$slave_id,".key" );
	if (optctx::interactive) {
		r = ::access(key_path.c_str(), F_OK);
		if (r == 0) {
			std::cerr << COLOR_YELLOW << "Replace the old key ? " << COLOR_RESET << " (Enter/Ctrl-C)" << std::flush;
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
		}
	}
#ifdef IOSLAVES_MASTER_KEYSTORE_EXT_METHODS
	dl_t pl_handle = NULL;
	iosl_master::keystore_api::key_store_f key_store_func = NULL;
		// Load key store method plugin
	if ($key_storage_method != "raw") {
		int r;
		std::string keystore_plugin_path = _S(IOSLAVES_MASTER_KEYSTORE_EXT_METHODS,'/',$key_storage_method,".ioslmcext");
		r = ::access(keystore_plugin_path.c_str(), R_OK);
		if (r == -1) {
			std::cerr << LOG_ARROW_ERR << "Key storage plugin '" << $key_storage_method << "' is not found" << std::endl;
			EXIT_FAILURE = EXIT_FAILURE_EXTERR;
			throw EXCEPT_ERROR_IGNORE;
		}
		pl_handle = ::dlopen(keystore_plugin_path.c_str(), RTLD_NOW|RTLD_LOCAL);
		if (pl_handle == NULL) {
			std::cerr << LOG_ARROW_ERR << "Can't load key storage plugin '" << keystore_plugin_path << "' : " << ::dlerror() << std::endl;
			EXIT_FAILURE = EXIT_FAILURE_SYSERR;
			throw EXCEPT_ERROR_IGNORE;
		}
		iosl_master::keystore_api::callbacks* callbacks = (iosl_master::keystore_api::callbacks*) ::dlsym(pl_handle, "api_callbacks");
		if (callbacks == NULL) {
			std::cerr << "Can't load api_callbacks structure of storage plugin '" << $key_storage_method << "' : " << ::dlerror() << std::endl;
			::dlclose(pl_handle);
			EXIT_FAILURE = EXIT_FAILURE_SYSERR;
			throw EXCEPT_ERROR_IGNORE;
		}
		callbacks->logstream_acquire = &xlog::logstream_acquire;
		callbacks->logstream_retrieve = &xlog::logstream_retrieve;
		callbacks->log_ostream = &xlog::__log__;
		callbacks->log_string = &xlog::__log__;
		__extension__ key_store_func = (iosl_master::keystore_api::key_store_f) ::dlsym(pl_handle, "key_store");
		if (key_store_func == NULL) {
			std::cerr << "Can't load key_store_func function of storage plugin '" << $key_storage_method << "' : " << ::dlerror() << std::endl;
			::dlclose(pl_handle);
			EXIT_FAILURE = EXIT_FAILURE_SYSERR;
			throw EXCEPT_ERROR_IGNORE;
		}
		std::cerr << LOG_ARROW_OK << "Key storage plugin '" << $key_storage_method << "' loaded" << std::endl;
	}
	RAII_AT_END_N(dl_close, {
		if (pl_handle != NULL) 
			::dlclose(pl_handle);
	});
#else
	if ($key_storage_method != "raw") {
		std::cerr << LOG_ARROW_ERR << "Other store method than 'raw' are impossible because key storage plugins support is disabled." << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_EXTERR;
		throw EXCEPT_ERROR_IGNORE;
	}
#endif
	{ // Execute storage method and write to key file
		fd_t f;
		f = ::open(key_path.c_str(), O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0600);
		if (f == -1)
			throw xif::sys_error("can't open key file for writing new key");
		FILE* ff = ::fdopen(f, "w");
		RAII_AT_END_N(file, {
			::fclose(ff);
			::close(f);
		});
		libconfig::Config key_c;
		key_c.getRoot().add("method", libconfig::Setting::TypeString) = $key_storage_method;
		libconfig::Setting& data_c = key_c.getRoot().add("data", libconfig::Setting::TypeGroup);
#ifdef IOSLAVES_MASTER_KEYSTORE_EXT_METHODS
		if (pl_handle != NULL) {
			try {
			(*key_store_func)($master_id+'.'+$slave_id,
			                  key,
			                  data_c);
			} catch (const std::runtime_error& e) {
				std::cerr << LOG_ARROW_ERR << "Error occured in keystore plugin '" << $key_storage_method << "' while storing new key : " << e.what() << std::endl;
				::dlclose(pl_handle);
				EXIT_FAILURE = EXIT_FAILURE_SYSERR;
				throw EXCEPT_ERROR_IGNORE;
			}
		} else
#endif
		{ // Raw key storage
			std::string key_hex = ioslaves::bin_to_hex(key.bin, KEY_LEN);
			data_c.add("key", libconfig::Setting::TypeString) = key_hex;
		}
		key_c.write(ff);
	}
	if (optctx::interactive) std::cout << LOG_ARROW_OK << "Key footprint of '" << key_path << "' : " << std::flush;
	unsigned char hash[MD5_DIGEST_LENGTH];
	::MD5(key.bin, KEY_LEN, hash);
	std::string footprint = ioslaves::bin_to_hex(hash, MD5_DIGEST_LENGTH);
	std::cerr << footprint << std::endl;
	if (optctx::interactive) {
		std::cout << "The key can be sent to the slave automatically with the authorization of an authorized master." << std::endl;
		std::cout << "For that, the key footprint must be sent to the master via an channel that guarantees integrity." << std::endl;
		std::cout << "You have " << IOSLAVES_KEY_SEND_DELAY << " seconds to send the key after the master sent the authorization." << std::endl;
		std::cout << LOG_ARROW << "Ready to send ?";
	_retry:
		std::cout << " (Enter/Ctrl-C)" << std::flush;
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
		try {
			socketxx::io::simple_socket<socketxx::base_netsock> slsock = 
				iosl_master::slave_connect($slave_id, 0, timeval({1,0}));
			slsock.o_bool(false);
			slsock.o_str($master_id);
			#warning TO DO : Must be encrypted
			slsock.o_buf(key.bin, KEY_LEN);
			ioslaves::answer_code o;
			o = (ioslaves::answer_code)slsock.i_char();
			if (o != ioslaves::answer_code::OK)
				throw o;
			std::cout << LOG_ARROW_OK << "Key is accepted ! Keep in mind : With great power comes great responsibility." << std::endl;
			try {
				std::string perms_str = slsock.i_str();
				std::cout << "Below are permissions associated with this key : \n--------------------\n" << perms_str << "\n--------------------" << std::endl;
			} catch (const socketxx::error&) {
				return;
			}
		} catch (const socketxx::error& e) {
			std::cerr << LOG_ARROW_ERR << "Network error while sending key : " << e.what() << std::endl;
			std::cout << LOG_ARROW << "Do you want to retry ?";
			goto _retry;
		}

	}
}

void ISlKeyAuth () {
	std::cerr << LOG_ARROW << "Authorizing master '" << $key_sl_master << "' to send its key with footprint " << $key_sl_auth_footprint << "..." << std::endl;
	$slave_sock->o_char((char)ioslaves::op_code::KEY_AUTH);
	$slave_sock->o_str($key_sl_auth_footprint);
	std::string perms_str;
	try {
		std::ifstream perms_f; perms_f.exceptions(std::ifstream::failbit|std::ifstream::badbit);
		perms_f.open($key_sl_auth_perms_file_path);
		perms_str = std::string (std::istreambuf_iterator<char>(perms_f),
		                         std::istreambuf_iterator<char>());
	} catch (const std::ifstream::failure& e) {
		std::cerr << LOG_ARROW_ERR << "Failed to read key permissions settings file : " << e.what() << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_SYSERR;
		throw EXCEPT_ERROR_IGNORE;
	}
	libconfig::Config perms_c;
	try {
		perms_c.readString(perms_str);
		perms_c.lookup("allow_by_default").assertType(libconfig::Setting::TypeBoolean);
		perms_c.lookup("allowed_ops").assertType(libconfig::Setting::TypeGroup);
		perms_c.lookup("denied_ops").assertType(libconfig::Setting::TypeArray);
	} catch (const libconfig::ParseException& e) {
		std::cerr << LOG_ARROW_ERR << "Parse error in permissions settings file at line " << e.getLine() << " : " << e.getError() << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_EXTERR;
		throw EXCEPT_ERROR_IGNORE;
	} catch (const libconfig::SettingException& e) {
		std::cerr << LOG_ARROW_ERR << "Missing/bad setting @" << e.getPath() << " in permissions settings file" << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_EXTERR;
		throw EXCEPT_ERROR_IGNORE;
	}
	$slave_sock->o_str(perms_str);
	$slave_sock->o_str($key_sl_master);
	$slave_sock->o_str($key_sl_auth_ip);
	ioslaves::answer_code o;
	o = (ioslaves::answer_code)$slave_sock->i_char();
	if (o != ioslaves::answer_code::OK)
		throw o;
	std::cerr << LOG_ARROW_OK << "Authorization acceped ! Waiting for sender master connection to slave (max " << IOSLAVES_KEY_SEND_DELAY << " seconds)..." << std::endl;
	$slave_sock->set_read_timeout(timeval({IOSLAVES_KEY_SEND_DELAY+1,0}));
	o = (ioslaves::answer_code)$slave_sock->i_char();
	if (o == ioslaves::answer_code::OK) {
		$key_sl_auth_ip = $slave_sock->i_str();
		std::cerr << LOG_ARROW_OK << "Key of master '" << $key_sl_master << "' (" << $key_sl_auth_ip << ") acceped !" << std::endl;
		delete $slave_sock;
		$slave_sock = NULL;
		return;
	}
	EXIT_FAILURE = EXIT_FAILURE_IOSL;
	switch (o) {
		case ioslaves::answer_code::DENY: std::cerr << COLOR_RED << "Key sender master was refused !" << COLOR_RESET << std::endl; break;
		case ioslaves::answer_code::TIMEOUT: std::cerr << COLOR_RED << "Key sender master did not connect in the 4s time window." << COLOR_RESET << std::endl; break;
		case ioslaves::answer_code::EXTERNAL_ERROR: std::cerr << COLOR_RED << "Communication error with key sender master." << COLOR_RESET << std::endl; break;
		default: throw o;
	}
	throw EXCEPT_ERROR_IGNORE;
}

void ISlKeyDel () {
	std::cerr << LOG_ARROW << "Deleting key of master master '" << $key_sl_master << "'..." << std::endl;
	$slave_sock->o_char((char)ioslaves::op_code::KEY_DEL);
	$slave_sock->o_str($key_sl_master);
}
		
	///---- Convert slave file to JSON ----////

void IioslFile2JSON () {
	int r;
	std::string fname = _S( IOSLAVES_MASTER_SLAVES_DIR,"/",$slave_id,".conf" );
	r = ::access(fname.c_str(), F_OK);
	if (r == -1) 
		std::cerr << COLOR_RED << "Slave settings file not found for '" << $slave_id << "'" << COLOR_RESET << std::endl;
	xif::polyvar infos;
	try {
		libconfig::Config conf;
		conf.readFile(fname.c_str());
		std::function< xif::polyvar(libconfig::Setting&) > conf_recuse = [&conf_recuse] (libconfig::Setting& sett) -> xif::polyvar {
			xif::polyvar var;
			switch (sett.getType()) {
				case libconfig::Setting::TypeArray:
				case libconfig::Setting::TypeList:
					var = xif::polyvar::vec();
					for (int i = 0; i < sett.getLength(); ++i) {
						var.v().push_back( conf_recuse(sett[i]) );
					}
					break;
				case libconfig::Setting::TypeGroup:
					var = xif::polyvar::map();
					for (int i = 0; i < sett.getLength(); ++i) {
						std::string name = sett[i].getName();
						var.m().insert( { name, conf_recuse(sett[i]) } );
					}
					break;
				case libconfig::Setting::TypeNone:
					break;
				case libconfig::Setting::TypeBoolean:
					var = sett.operator bool();
					break;
				case libconfig::Setting::TypeInt64:
					var = sett.operator long long();
					break;
				case libconfig::Setting::TypeInt:
					var = sett.operator int();
					break;
				case libconfig::Setting::TypeFloat:
					var = sett.operator float();
					break;
				case libconfig::Setting::TypeString:
					var = sett.operator std::string();
					break;
			}
			return var;
		};
		xif::polyvar var = conf_recuse(conf.libconfig::Config::getRoot());
		std::cout << var.to_json(3) << std::endl;
	} catch (const std::exception& e) {
		std::cerr << COLOR_RED << "Setting error in conf file of '" << $slave_id << "'" << COLOR_RESET << " : " << e.what() << std::endl;
	}
}

	///---- Bye ----///

void IPost (ioslaves::answer_code e) {
	if (e == EXCEPT_ERROR_IGNORE) throw EXCEPT_ERROR_IGNORE;
	if (e != ctx_postfnct_excpt_default) {
		switch (e) {
			case ioslaves::answer_code::OK: std::cerr << COLOR_GREEN << "Success !" << COLOR_RESET << std::endl; break;
			case ioslaves::answer_code::MAY_HAVE_FAIL: std::cerr << COLOR_YELLOW << "Operation may have failed !" << COLOR_RESET << std::endl; break;
			default: goto __error;
		}
		return;
	__error:
		EXIT_FAILURE = EXIT_FAILURE_IOSL;
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
			case ioslaves::answer_code::DENY: errstr = "Action refused by slave !"; break;
			case ioslaves::answer_code::BAD_CHALLENGE_ANSWER: errstr = "Authentication failed !"; break;
			case ioslaves::answer_code::EXTERNAL_ERROR: errstr = "Slave external error !"; break;
			case ioslaves::answer_code::INVALID_DATA: errstr = "Invalid data !"; break;
			case ioslaves::answer_code::LACK_RSRC: errstr = "Lacking ressources !"; break;
			case ioslaves::answer_code::TIMEOUT: errstr = "Timeout !"; break;
			case ioslaves::answer_code::NOT_AUTHORIZED: errstr = "Permission denied !"; break;
			default: case ioslaves::answer_code::ERROR: errstr = "Unknown error !";
		}
		std::cerr << COLOR_RED << errstr << COLOR_RESET << std::endl;
		throw EXCEPT_ERROR_IGNORE;
	}
}
