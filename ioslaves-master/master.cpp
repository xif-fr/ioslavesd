/**********************************************************\
 *               -== Xif Network project ==-
 *                      ioslaves-master
 *            Ioslaves Control Program for Masters
 * *********************************************************
 * Copyright © Félix Faisant 2013-2014. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common
#define IOSLAVES_MASTER_FINAL
#include "master.hpp"

	// Other
#include <memory>
#include <xifutils/polyvar.hpp>
#include <string.h>
#include <stdio.h>
#include <iostream>

	// Config
#include <libconfig.h++>

	// Files
#include <sys/stat.h>

	// Network
#include <socket++/handler/socket_client.hpp>
#include <socket++/handler/socket_server.hpp>
#include <socket++/io/tunnel.hpp>
#include <socket++/base_unixsock.hpp>
#include <socket++/base_inet.hpp>
#include <socket++/quickdefs.h>

	// Log
pthread_mutex_t xlog::logstream_impl::mutex = PTHREAD_MUTEX_INITIALIZER;
std::ostringstream xlog::logstream_impl::stream;
bool _log_wait_flag = false;
void xlog::logstream_impl::log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid) noexcept {
	if (_log_wait_flag and not (m & LOG_ADD)) { std::clog << std::endl; _log_wait_flag = false; }
	switch (lvl) {
		case log_lvl::LOG: case log_lvl::NOTICE: case log_lvl::IMPORTANT: case log_lvl::MAJOR: break;
		case log_lvl::FATAL: case log_lvl::ERROR: case log_lvl::OOPS: std::clog << COLOR_RED << "Error : " << COLOR_RESET; break;
		case log_lvl::WARNING: std::clog << COLOR_YELLOW << "Warning : " << COLOR_RESET; break;
		case log_lvl::DONE: std::clog << COLOR_GREEN << "Done ! " << COLOR_RESET; break;
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
uint16_t $on_psu_id = -1;
std::string $new_key_file_path;
std::string $api_co_unix_sock_path;
bool $need_auth = false;
timeval $connect_timeout = {1,000000};
timeval $comm_timeout = {4,000000};
bool $ignore_net_errors = false;
time_t $log_begin, $log_end;
int16_t $autoshutdown = -1;

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
	void IPostSlaveCo (ioslaves::answer_code);
	void IKeygen ();
	void IPowerup ();
void IPost (ioslaves::answer_code);

	// Commmand line arguments
#define OPTCTX_IMPL

#define OPTCTX_POSTFNCT_EXCEPT_T ioslaves::answer_code
#define OPTCTX_POSTFNCT_EXCEPT_DEFAULT (ioslaves::answer_code)0
#define EXCEPT_ERROR_IGNORE (ioslaves::answer_code)1

#define OPTCTX_CTXS                              slctrl                         , slctrl_Ser                     , slctrl_Sstart    , slctrl_Sstop    , slctrl_Sapi       , slctrl_port , slctrl_shutd , slctrl_stat , slctrl_log , keygen        , powerup
#define OPTCTX_PARENTS                           ROOT                           , slctrl                         , slctrl_Ser       , slctrl_Ser      , slctrl_Ser        , slctrl      , slctrl       , slctrl      , slctrl     , ROOT          , ROOT
#define OPTCTX_PARENTS_NAMES  "action"         , "slave command"                , "service opperation"           , NULL             , NULL            , NULL              , NULL        , NULL         , NULL        , NULL       , NULL          , NULL
#define OPTCTX_PARENTS_FNCTS  CTXFP(NULL,IPost), CTXFP(IPreSlaveCo,IPostSlaveCo), CTXFP(IPreService,IPostService), CTXFO(IServStart), CTXFO(IServStop), CTXFO(IApi)       , CTXFO(IPort), CTXFO(IShutd), CTXFO(IStat), CTXFO(ILog), CTXFO(IKeygen), CTXFO(IPowerup)
#define OPTCTX_NAMES                             "--control"                    , "--service"                    , "--start"        , "--stop"        , "--api-service-co", "--xxx-port", "--shutdown" , "--status"  , "--log"    , "--add-key"   , "--on"   

#define OPTCTX_PROG_NAME "ioslaves-master"
#include <xifutils/optctx.hpp>

inline void try_parse_IDs (int argc, char* const argv[]) {
	if (not $master_id.empty()) return;
	if (argc == optind || argv[optind][0] == '-') 
		return;
	$master_id = argv[optind++];
	if (!ioslaves::validateSlaveName($master_id)) 
		try_help("ioslave-master: invalid master ID\n");
	if (argc == optind || argv[optind][0] == '-') 
		try_help("ioslave-master: excepted slave ID after master ID\n");
	std::string slave_addr = argv[optind++];
	size_t pos = 0;
	if ((pos = slave_addr.find_first_of('@')) != std::string::npos) {
		$slave_id = slave_addr.substr(0,pos);
		slave_addr = slave_addr.substr(pos+1);
	}
	if (slave_addr.find_first_of('.') != std::string::npos) {
		try {
			$connect_addr = socketxx::base_netsock::addr_info ( IOSLAVES_MASTER_DEFAULT_PORT, slave_addr );
		} catch (socketxx::bad_addr_error& e) {
			try_help("ioslave-master: invalid slave address\n");
		} catch (socketxx::dns_resolve_error& e) {
			std::cerr << COLOR_RED << "Can't resolve slave hostname '" << e.failed_hostname << "' !" << COLOR_RESET << std::endl;
			::exit(EXIT_FAILURE_CONN);
		}
		$addr_defined = true;
	} else {
		if (!ioslaves::validateSlaveName(slave_addr)) 
			try_help("ioslave-master: invalid slave ID\n");
		$slave_id = slave_addr;
	}
}
inline void test_for_IDs () {
	if ($master_id.empty())
		try_help("ioslave-master: master and slave IDs requiered\n");
}

int main (int argc, char* const argv[]) {
	
	struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"verbose", no_argument, NULL, 'v'},
		{"no-interactive", no_argument, NULL, 'i'},
		{"control", no_argument, NULL, 'C'},
			{"force-auth", no_argument, NULL, 'f'},
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
		{"keygen", no_argument, NULL, 'K'},
		{"on", optional_argument, NULL, 'O'},
		{NULL, 0, NULL, 0}
	};
	
	{ int r;
		r = ::access(_s(IOSLAVES_MASTER_DIR), F_OK);
		if (r == -1) {
			r = ::mkdir(_s(IOSLAVES_MASTER_DIR), 0740);
			if (r == -1) {
				std::cerr << COLOR_RED << "Can't create ioslaves-master directory" << COLOR_RESET << " (" << IOSLAVES_MASTER_DIR << ") : " << ::strerror(errno) << std::endl;
				return EXIT_FAILURE;
			}
		}
	}
	
	try_parse_IDs(argc, argv);
	
	int opt, opt_charind = 0;
	while ((opt = ::getopt_long(argc, argv, "-hviCfp:S:soa:P:X:RDGL::KO::", long_options, &opt_charind)) != -1) {
		switch (opt) {
			case 'h':
				::puts("ioslaves-master | ioslaves control programm for network masters\n"
						 "Usage: ioslaves-master MASTER-ID SLAVE-ID/ADDR --ACTION [--COMMAND [OPTIONS] ...]\n"
						 "\n"
						 "General options :\n"
						 "      MASTER-ID             The master ID, used for authentification.\n"
						 "      SLAVE-ID/ADDR         If the slave ID is used, IP and port are automatically retrieved.\n"
						 "                            Else, the ADDR can be an IP or an hostname, with optionally :PORT\n"
						 "  -i, --no-interactive      Disable prompting. Log in HTML.\n"
						 "\n"
						 "Actions :\n"
						 "  -C, --control             Connect to distant ioslaves server. Authentification is optional but\n"
						 "                             needed for most opperations.\n"
						 "      Options :\n"
						 "        -f, --force-auth        Force authentification even if the opperation don't need it.\n"
						 "      Commands :\n"
						 "        -S, --service=SERVICE   Control slave's services\n"
						 "            Opperations :\n"
						 "               -s, --start          Start service\n"
						 "               -o, --stop           Stop service\n"
						 "               -a, --api-service-co=UNIX_SOCK\n"
						 "                                    Get connection to an ioslaves API service. ioslaves role\n"
						 "                                     here is only a relay between the distant API service and\n"
						 "                                     a progam that knows the service's protocol, via unix socket.\n"
						 "        -P, --open-port=(T|U)PORT[-END] [DESCR]\n"
						 "                                    Open port(s) (TCP/UDP) on the distant slave's gatway using UPnP.\n"
						 "        -X, --close-port=(T|U)PORT[-END]\n"
						 "                                    Close opened port(s) on the distant gateway.\n"
						 "        -R, --reboot                Reboot distant slave.\n"
						 "        -D, --shutdown [AUTO_TIME]  Shutdown distant slave. AUTO_TIME param manages automatic\n"
						 "                                     shutdown. If AUTO_TIME=0, inhibits auto-shutdown. If AUTO_TIME>0,\n"
						 "                                     sets the automatic shutdown in AUTO_TIME minutes.\n"
						 "        -G, --status                Report overview status of the slave as JSON.\n"
						 "        -L, --log [BEGIN[-END]]      Get slave's log line from timestamps BEGIN to END\n"
						 "                                     (0 for no limit). Returns JSON if not interactive.\n"
						 "  -K, --keygen             Generate (and replace if exists) a key for the slave. The key need to\n"
						 "                            copied on the slave.\n"
						 "  -O, --on [METHOD ARG[s]] Power on slave using several methods :\n"
						 "                            MAGIC_PKT: wake up the slave using a magic packet containing the\n"
						 "                                        MAC address of its compatible NIC (UDP packet on port 9).\n"
						 "                                       If the 2nd arg is defined, the packet is sent on represented\n"
						 "                                        hostname instead of the broadcast addr of the local network.\n"
						 "                                       If sent to the WAN, the router must support it.\n"
						 "                            MAGIC_GATEWAY: tell the 'wol' ioslavesd plugin of a slave on the same\n"
						 "                                           network to send a WoL packet. Used if the magic packet\n"
						 "                                           cannot traverse the NAT. Takes gateway's name or address.\n"
						 "                            SERIAL_PSU: command a centralized PSU via serial port using xif PSU's\n"
						 "                                        protocol. Takes the output ID of the PSU.\n"
						 "\n");
				return EXIT_SUCCESS;
			case 'i':
				optctx::interactive = false;
				try_parse_IDs(argc, argv);
				break;
			case 'C':
				optctx::optctx_set(optctx::slctrl);
				test_for_IDs();
				break;
			case 'f':
				optctx::optctx_test("--auth-force", optctx::slctrl);
				$need_auth = true;
				break;
			case 'S':
				optctx::optctx_set(optctx::slctrl_Ser);
				$need_auth = true;
				$service_name = optarg;
				if (!ioslaves::validateName($service_name)) {
					try_help("--service: invalid service ID\n");
				}
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
				$need_auth = true;
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
				$need_auth = true;
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
				$need_auth = true;
				break;
			case 'G':
				optctx::optctx_set(optctx::slctrl_stat);
				break;
			case 'L': {
				optctx::optctx_set(optctx::slctrl_log);
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
						try_help("--log : invalid timestamps\n");
					}
				}
			} break;
			case 'K': {
				optctx::optctx_set(optctx::keygen);
				test_for_IDs();
				if ($slave_id.empty()) 
					try_help("--keygen : must use a slave ID\n");
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
						} catch (socketxx::bad_addr_error) {
							try_help("--on=MAGIC_PKT : second arg must be a valid IP addr or hostname\n");
						} catch (socketxx::dns_resolve_error& e) {
							std::cerr << COLOR_RED << "Can't resolve slave hostname '" << e.failed_hostname << "' !" << COLOR_RESET << std::endl;
							::exit(EXIT_FAILURE_CONN);
						}
					}
				} 
				else if (on_str_type == "MAGIC_GATEWAY") {
					$poweron_type = iosl_master::on_type::GATEWAY;
					if (optind == argc or argv[optind][0] == '-') 
						try_help("--on=MAGIC_GATEWAY must take gateway's name or hostname as argument\n");
					$on_gateway = argv[optind++];
					if (not ioslaves::validateHostname($on_gateway))
						try_help("--on=MAGIC_GATEWAY : invalid gateway hostname\n"); 
				} 
				else if (on_str_type == "SERIAL_PSU") {
					$poweron_type = iosl_master::on_type::PSU;
					if (optind == argc or argv[optind][0] == '-') 
						try_help("--on=SERIAL_PSU must take PSU output ID as argument\n");
					try {
						$on_psu_id = ::atoix<uint16_t>(argv[optind++]);
					} catch (std::runtime_error) {
						try_help("--on=SERIAL_PSU : PSU output ID must be a number\n");
					}
				} else if (not on_str_type.empty()) {
					try_help("--on : invalid mode\n");
				}
			} break;
			default: 
				try_help();
		}
	}
	optctx::optctx_end();
	
	#warning TO DO : auth
	/*if ($need_auth and $slave_id.empty()) {
		std::cerr << COLOR_RED << "Authentification needed : must use a slave ID !" << COLOR_RESET << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_AUTH;
		return EXIT_FAILURE;
	}*/
	
	/// Execute
	try {
		optctx::optctx_exec();
	} catch (socketxx::error& se) {
		if ($ignore_net_errors) return EXIT_SUCCESS;
		std::cerr << COLOR_RED << "network error : " << COLOR_RESET << se.what() << std::endl;
		return EXIT_FAILURE_COMM;
	} catch (std::runtime_error& re) {
		std::cerr << COLOR_RED << "ioslaves-master error : " << COLOR_RESET << re.what() << std::endl;
		return EXIT_FAILURE;
	} catch (ioslaves::answer_code) {
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
		if (not $slave_id.empty() and not $addr_defined) {
			in_port_t $connect_port = IOSLAVES_MASTER_DEFAULT_PORT;
			try { // Retriving port number with SRV records
				std::cerr << "Retriving port number from SRV record _ioslavesd._tcp." << $slave_id << '.' << XIFNET_SLAVES_DOM << "..." << std::endl;
				$connect_port = iosl_master::slave_get_port_dns($slave_id);
			} catch (iosl_master::ldns_error& e) {
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
	} catch (socketxx::dns_resolve_error& e) {
		std::cerr << COLOR_RED << "Can't resolve hostname '" << e.failed_hostname << "' !" << COLOR_RESET << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_CONN; throw EXCEPT_ERROR_IGNORE;
	}
		// Connecting
	std::string slave_name = ($slave_id.empty()) ? "slave" : _S('`',$slave_id,'`');
	try {
		std::cerr << "Connecting to " << slave_name << " at " << $connect_addr.get_ip_str() << ":" << $connect_addr.get_port() << "..." << std::endl;
		$slave_sock = new socketxx::simple_socket_client<socketxx::base_netsock> ($connect_addr, $connect_timeout);
		$slave_sock->set_read_timeout($comm_timeout);
	} catch (socketxx::error& e) {
		std::cerr << COLOR_RED << "Failed to connect to slave : " << COLOR_RESET << e.what() << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_CONN;
		delete $slave_sock;
		throw EXCEPT_ERROR_IGNORE;
	}
	try {
		$slave_sock->o_bool(true);
			// Authentification
		$slave_sock->o_str($master_id);
#warning TO DO : Auth
$need_auth = false;
		$slave_sock->o_bool($need_auth);
		if ($need_auth) {
			std::cerr << "Authentification..." << std::endl;
			iosl_master::authentificate(*$slave_sock, $slave_id);
		}
	} catch (socketxx::error& e) {
		std::cerr << COLOR_RED << "Failed to communicate with " << slave_name << " : " << COLOR_RESET << e.what() << std::endl;
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
	std::cerr << "Managing slave's service '" << $service_name << "'" << std::endl;
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
		case ioslaves::answer_code::BAD_TYPE: std::cerr << COLOR_RED << "Opperation inapplicable : bad service type" << COLOR_RESET << std::endl; break;
		case ioslaves::answer_code::BAD_STATE: std::cerr << COLOR_RED << "Opperation inapplicable : bad service state" << COLOR_RESET << std::endl; break;
		case ioslaves::answer_code::NOT_FOUND: std::cerr << COLOR_RED << "Service not found" << COLOR_RESET << std::endl; break;
		case ioslaves::answer_code::EXTERNAL_ERROR: std::cerr << COLOR_RED << "Failed to opperate on this service !" << COLOR_RESET << std::endl; break;
		default: throw answ;
	}
	throw EXCEPT_ERROR_IGNORE;
}

	///---- API services ----///

void api_tunnel_intercept_fnct (bool this_to_other, void** buf, size_t* len, size_t max_buf_len);
void IApi () {
	std::cerr << "Connecting to API service..." << std::endl;
	$slave_sock->o_char((char)ioslaves::op_code::CALL_API_SERVICE);
	$slave_sock->o_str($service_name);
	try {
		IPostService(ctx_postfnct_excpt_default);
	} catch (ioslaves::answer_code& e) {
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
		case ioslaves::answer_code::MAY_HAVE_FAIL: std::cerr << COLOR_YELLOW << "UPnP Opperation may have fail, but on some gateways it's OK" << COLOR_RESET << std::endl; return;
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
	std::cout << info.to_json().c_str() << std::endl;
}

const char* log_lvl_strs[] = { "FATAL", "ERROR", "OOPS", "WARNING", "NOTICE", "LOG", "IMP", "MAJOR", "DONE" };
void ILog () {
	std::cerr << "Getting slave's log lines from " << $log_begin << " to " << $log_end << "..." << std::endl;
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
		if ($slave_id.empty()) {
			std::cerr << COLOR_RED << "Power up : slave ID must be defined" << COLOR_RESET << std::endl;
			throw EXCEPT_ERROR_IGNORE;
		}
		bool up = iosl_master::slave_test($slave_id);
		if (up) {
			std::cerr << COLOR_YELLOW << "Slave '" << $slave_id << "' is already up !" << std::endl;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
			throw EXCEPT_ERROR_IGNORE;
		}
		time_t delay;
		try {
			delay = iosl_master::slave_start($slave_id);
		} catch (std::exception& e) {
			std::cerr << COLOR_RED << "Power up error" << COLOR_RESET << " : " << e.what() << std::endl;
			EXIT_FAILURE = EXIT_FAILURE_IOSL;
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
				EXIT_FAILURE = EXIT_FAILURE_IOSL;
				throw EXCEPT_ERROR_IGNORE;
			}
		} else {
			std::cout << ::ixtoa(delay) << std::endl;
		}
	} else {
		if ($poweron_type == iosl_master::on_type::WoW) {
			ioslaves::wol::magic_send($on_mac.c_str(), true, $connect_addr.get_ip_addr().s_addr, $connect_addr.get_port());
		} else if ($poweron_type == iosl_master::on_type::WoL) {
			ioslaves::wol::magic_send($on_mac.c_str(), false);
		} else if ($poweron_type == iosl_master::on_type::GATEWAY) {
			#warning TO DO : wol gateway connection
		} else if ($poweron_type == iosl_master::on_type::PSU) {
			#warning TO DO : serial psu module
		}
	}
	} catch (std::exception& e) {
		std::cerr << COLOR_RED << "Power up error" << COLOR_RESET << " : " << e.what() << std::endl;
		EXIT_FAILURE = EXIT_FAILURE_IOSL;
		throw EXCEPT_ERROR_IGNORE;
	}
}

	///---- Keys ----///

void IKeygen () {
	std::cerr << "Generating key for slave '" << $slave_id << "'..." << std::endl;
	std::string key;
	key += ioslaves::hash($slave_id);
	key += ioslaves::hash($master_id);
	key += ioslaves::generate_random(384);
	int r;
	r = ::access(IOSLAVES_MASTER_KEYS_DIR, F_OK);
	if (r == -1) {
		r = ::mkdir(IOSLAVES_MASTER_KEYS_DIR, 0700);
		if (r == -1) throw xif::sys_error("can't create keys dir");
	}
	std::string key_path = _S( IOSLAVES_MASTER_KEYS_DIR,"/",$slave_id,".key" );
	if (optctx::interactive) {
		r = ::access(key_path.c_str(), F_OK);
		if (r == 0) {
			std::cerr << COLOR_YELLOW << "Replacing old key ? " << COLOR_RESET << " (Enter/Ctrl-C)" << std::flush;
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
		}
	}
	fd_t f;
	f = ::open(key_path.c_str(), O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0600);
	if (f == -1)
		throw xif::sys_error("can't open key file for writing new key");
	ssize_t rs = ::write(f, key.c_str(), key.size());
	if (rs != (ssize_t)key.size())
		throw xif::sys_error("failed to write into key file");
	::close(f);
	if (optctx::interactive) std::cerr << "Key footprint of '" << key_path << "' : " << std::flush;
	std::cout << ioslaves::md5(key) << std::endl;
}

	///---- Bye ----///

void IPost (ioslaves::answer_code e) {
	if (e == EXCEPT_ERROR_IGNORE) throw EXCEPT_ERROR_IGNORE;
	if (e != ctx_postfnct_excpt_default) {
		switch (e) {
			case ioslaves::answer_code::OK: std::cerr << COLOR_GREEN << "Success !" << COLOR_RESET << std::endl; break;
			case ioslaves::answer_code::MAY_HAVE_FAIL: std::cerr << COLOR_YELLOW << "Opperation may have fail !" << COLOR_RESET << std::endl; break;
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
			case ioslaves::answer_code::BAD_STATE: errstr = "Opperation inapplicable : bad state !"; break;
			case ioslaves::answer_code::BAD_TYPE: errstr = "Opperation inapplicable : bad type !"; break;
			case ioslaves::answer_code::WANT_REPORT: errstr = "Slave want to report something : can't handle request"; break;
			case ioslaves::answer_code::WANT_GET: errstr = "Slave want to get something : can't handle request"; break;
			case ioslaves::answer_code::WANT_SEND: errstr = "Slave want to tranfer something : can't handle request"; break;
			case ioslaves::answer_code::OP_NOT_DEF: errstr = "Opperation not defined !"; break;
			case ioslaves::answer_code::EXISTS: errstr = "Already exists !"; break;
			case ioslaves::answer_code::UPNP_ERROR: errstr = "Port mapping error !"; break;
			case ioslaves::answer_code::DENY: errstr = "Action refused by slave !"; break;
			case ioslaves::answer_code::BAD_CHALLENGE_ANSWER: errstr = "Authentification failed !"; break;
			case ioslaves::answer_code::EXTERNAL_ERROR: errstr = "Slave external error !"; break;
			case ioslaves::answer_code::INVALID_DATA: errstr = "Invalid data !"; break;
			case ioslaves::answer_code::LACK_RSRC: errstr = "Lacking ressources !"; break;
			default: case ioslaves::answer_code::ERROR: errstr = "Unknown error !";
		}
		std::cerr << COLOR_RED << errstr << COLOR_RESET << std::endl;
		throw EXCEPT_ERROR_IGNORE;
	}
}
