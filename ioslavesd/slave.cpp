/**********************************************************\
 *               -== Xif Network project ==-
 *                       ioslavesd
 *        slave control deamon and services manager
 * *********************************************************
 * Copyright © Félix Faisant 2013-2015. All rights reserved
 * This software is under the GNU General Public License
\**********************************************************/

	// Common
#define IOSLAVESD_API_MAIN_PROG_IMPL
#include "main.h"
using namespace xlog;

	// ioslaves-master API
#include "master.hpp"

	// General
#include <vector>
#include <list>
#include <map>
#include <set>
#include <stdlib.h>
#include <unistd.h>
#include <typeinfo>
#include <xifutils/cxx.hpp>
#include <xifutils/intstr.hpp>

	// Time
#define IOSL_SHUTDOWN_CHK_INTERVAL 2*60
#define IOSL_CLI_DELAY_AUTH 0//s
#define IOSL_CLI_DELAY_NO_AUTH 2//s
#define IOSL_CLI_DELAY_FAIL_AUTH 10//s
#define IOSL_CLI_DELAY_REST_TRY 2//s

	// Crypto
#include <openssl/whrlpool.h>
#include <openssl/md5.h>

	// Files
#include <sys/file.h>
#include <sys/dir.h>
#define private public
#include <libconfig.h++>
#undef private

	// Process
#include <sys/sysctl.h>
#ifdef __APPLE__
	#include <libproc.h>
#endif

	// Threads and signals
#include <signal.h>
#include <sys/wait.h>
fd_t serv_stop_pipe[2] = {INVALID_HANDLE,INVALID_HANDLE};
void* signals_thread (void* _data);

	// Services
std::list<ioslaves::service*> ioslaves::services_list;
std::set<std::string> allowed_api_services;

	// Network
#include <socket++/handler/socket_server.hpp>
#include <socket++/handler/socket_client.hpp>
#include <socket++/quickdefs.h>
#define IN_LISTENING_PORT ioslavesd_listening_port
#define IN_LISTENING_IP inaddr_any
#define IN_ACCEPT_MAX_WAITING_CLIENTS 10
#define IN_CLIENT_TIMEOUT {1,500000}
#define IN_CLIENT_AUTH_TIMEOUT {4,0}
#define POOL_TIMEOUT {1,0}
in_port_t ioslavesd_listening_port = 2929;

	// Sched threads
sig_atomic_t sched_threads_run = true;
std::list<socketxx::simple_socket_server<socketxx::base_netsock,void>::client> status_clients;
pthread_mutex_t status_clients_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t status_thread_handle;
void* status_thread (void*);
pthread_t port_thread_handle;
void* port_thread (void*);

	// User
#include <pwd.h>
#define IOSLAVES_USER "ioslaves"
uid_t ioslaves_user_id = 0;
gid_t ioslaves_group_id = 0;
#ifdef __linux__
#include <sys/syscall.h>
#ifdef __x86_64__
	#define SYS_setresuid32 SYS_setresuid
	#define SYS_setresgid32 SYS_setresgid
#endif
#include <unistd.h>
void ioslaves::api::euid_switch (uid_t uid, gid_t gid) {
	int errsave = errno;
	if (uid == -1 and gid == -1) {
		uid = ioslaves_user_id;
		gid = ioslaves_group_id;
	}
	uid_t curuid = ::geteuid();
	gid_t curgid = ::getegid();
	if (curuid == uid and curgid == gid) {
		__log__(log_lvl::LOG, "EUID", logstream << "Keeping uid " << ::geteuid() << "/gid " << ::getegid(), LOG_DEBUG);
		return;
	}
	if (uid != 0 and curuid != 0) 
		ioslaves::api::euid_switch(0, 0);
	__log__(log_lvl::LOG, "EUID", logstream << "Setting uid/gid to " << uid << "/" << gid, LOG_DEBUG);
	bool set = uid == 0;
	long r = ::syscall( (set? SYS_setresuid32 : SYS_setresgid32), (int)-1, (int)(set? uid : gid), (int)-1 ) 
	       | ::syscall( (set? SYS_setresgid32 : SYS_setresuid32), (int)-1, (int)(set? gid : uid), (int)-1 );
	if (r != 0)
		__log__(log_lvl::SEVERE, "EUID", logstream << "Failed to set uid/gid to " << uid << "/" << gid << " : " << ::strerror(errno));
	errno = errsave;
}
#else
void ioslaves::api::euid_switch (uid_t uid, gid_t gid) {
	#warning No thread-specific EUID switching possible
}
#endif

	// Vars
char hostname[64];
short ip_refresh_dyndns_interval = -1;
in_addr ip_refresh_dyndns_server = {0};
std::string dyndns_slave_key_id = IOSLAVESD_DNS_SLAVE_KEY_ID_DEFAULT_NAME;
bool shutdown_ignore_err = false;
time_t shutdown_iosl_time = 0;
time_t start_iosl_time = 0;
enum { QUIT_NORMAL, QUIT_SHUTDOWN, QUIT_REBOOT } quit_type = QUIT_NORMAL;
std::map<in_addr_t, time_t> conn_next_delay;
	// API vars
ioslaves::api::common_vars_t ioslaves::api::api_vars = {
	.system_stat = &ioslaves::system_stat,
	.shutdown_iosl_time = &shutdown_iosl_time,
};

	/// Main
int main (int argc, const char* argv[]) {
	int r;
	ssize_t rs;
	logl_t l;
	start_iosl_time = ::iosl_time();
	
		// Global exception handler
	try {
	log_file_path = IOSLAVESD_LOG_FILE;
	
		// Create log file if doesn't exist
	fd_t fd_log = ::open(log_file_path, O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW, 0644);
	if (fd_log == -1) 
		throw xif::sys_error("can't initially open/create log file");
	::close(fd_log);

		// ioslaves user
	if (::getuid() == 0) {
		#if defined(__linux__)
		long _pwbufsz = ::sysconf(_SC_GETPW_R_SIZE_MAX);
		if (_pwbufsz < 1) _pwbufsz = 100;
		char pwbuf[_pwbufsz];
		struct passwd userinfo, *_p_userinfo;
		r = ::getpwnam_r(IOSLAVES_USER, &userinfo, pwbuf, _pwbufsz, &_p_userinfo);
		if (r == -1 or _p_userinfo == NULL) 
			__log__(log_lvl::MAJOR, NULL, logstream << "Starting ioslavesd as root (user '" IOSLAVES_USER "' not found)...", LOG_WAIT, &l);
		else {
			ioslaves_user_id = userinfo.pw_uid;
			ioslaves_group_id = userinfo.pw_gid;
			r = ::chown(IOSLAVESD_LOG_FILE, (uid_t)ioslaves_user_id, (gid_t)ioslaves_group_id);
			if (r == -1 and errno != ENOENT) 
				__log__(log_lvl::WARNING, "SEC", logstream << "Failed to chown log file : " << ::strerror(errno));	
			r = ::setegid(ioslaves_user_id)
			  | ::seteuid(ioslaves_group_id);
			if (r != 0) {
				__log__(log_lvl::SEVERE, "SEC", logstream << "Failed to set effective uid/gid to user '" IOSLAVES_USER "' : " << ::strerror(errno));	
				ioslaves_user_id = ioslaves_group_id = 0;
			} else
				__log__(log_lvl::MAJOR, NULL, logstream << "Starting ioslavesd as user '" IOSLAVES_USER "'...", LOG_WAIT, &l);
		}
		#else
			__log__(log_lvl::MAJOR, NULL, logstream << "Starting ioslavesd as root (isolaved thread credentials not supported)...", LOG_WAIT, &l);
		#endif
	} else {
		__log__(log_lvl::MAJOR, NULL, logstream << "Starting ioslavesd as uid " << ::getuid() << "...", LOG_WAIT, &l);
	}
	
		// Hostname
	::gethostname(hostname, sizeof(hostname));
	for (size_t i = 0; i < ::strlen(hostname); i++) 
		if (hostname[i] == '.') { hostname[i] = '\0'; break; }
	
		// Create PID file
	const char* pid_file = IOSLAVESD_RUN_FILES"/ioslavesd.pid";
	fd_t f_pid = -1;
	{ asroot_block();
		f_pid = ::open(pid_file, O_CREAT|O_RDWR|O_EXCL|O_NOFOLLOW|O_SYNC, 0644);
		if (f_pid != -1) {
			r = ::fchown(f_pid, (uid_t)ioslaves_user_id, (gid_t)ioslaves_group_id);
			if (r == -1) {
				__log__(log_lvl::FATAL, NULL, logstream << "Can't chown PID file : " << ::strerror(errno));
				return EXIT_FAILURE;
			}
		}
	}
	if (f_pid == -1) {
		if (errno == EEXIST) {
			__log__(log_lvl::WARNING, NULL, logstream << "PID file at " << pid_file << " already exists ! Checking lock...");
			f_pid = ::open(pid_file, O_RDWR|O_NOFOLLOW|O_SYNC);
		}
		if (f_pid == -1) {
			__log__(log_lvl::FATAL, NULL, logstream << "Can't create PID file : " << ::strerror(errno));
			return EXIT_FAILURE;
		}
	}
	r = ::flock(f_pid, LOCK_EX|LOCK_NB);
	if (r == -1 and errno == EWOULDBLOCK) {
		__log__(log_lvl::FATAL, NULL, logstream << "PID file is locked, ioslavesd seems to be already running !");
		return EXIT_FAILURE;
	}
	::ftruncate(f_pid, (size_t)0);
	pid_t pid = ::getpid();
	std::string pid_str = ::ixtoa(pid);
	rs = ::write(f_pid, pid_str.c_str(), pid_str.length());
	if (rs != (ssize_t)pid_str.length()) {
		__log__(log_lvl::FATAL, NULL, logstream << "Can't write to PID file : " << ::strerror(errno));
		return EXIT_FAILURE;
	}
	RAII_AT_END_N(pidfile, {
		if (f_pid != -1) {
			::close(f_pid);
			ioslaves::api::euid_switch(0,0);
			::unlink(pid_file);
		}	
	});
	
		// Create signals thread
	signal_catch_sigchild_p = new sig_atomic_t (true);
	pthread_t sig_thread;
	r = ::pthread_create(&sig_thread, NULL, signals_thread, NULL);
	if (r != 0)
		throw xif::sys_error("failed to create signals thread", r);
	
		// Conf file
	__log__(log_lvl::LOG, NULL, logstream << "Loading conf file...", LOG_ADD, &l);
	libconfig::Config conf;
	try {
		conf.readFile(IOSLAVESD_CONF_FILE);
		{
			enable_upnp = (bool)conf.lookup("upnp_port_opening");
			if (enable_upnp) {
				ports_reopen_interval = (time_t)(int)conf.lookup("upnp_igd_port_reopen_interval");
				if (ports_reopen_interval != 0) {
					if (ports_reopen_interval <= 20) {
						__log__(log_lvl::ERROR, "CONF", logstream << "Ports reopen interval too short");
						return 1;
					}
					ports_reopen_justafter = (bool)conf.lookup("upnp_igd_port_reopen_justafter");
					ports_reopen_interval += (ports_reopen_justafter) ? (+2) : (-10);
				}
				ioslavesd_listening_port_open = !(bool)conf.lookup("listening_port_already_opened");
				try {
					upnp_cache_deviceurl = (bool)conf.lookup("upnp_cache_igd_url");
				} catch (...) {}
				try {
					ports_check_interval = (time_t)(int)conf.lookup("upnp_ports_check_interval");
				} catch (...) {}
			}
			ioslavesd_listening_port = (in_port_t)(int)conf.lookup("listening_port");
			try {
				ip_refresh_dyndns_interval = (int)conf.lookup("dyndns_refresh_interval");
			} catch (...) {}
			if (ip_refresh_dyndns_interval >= 0) {
				try {
					ip_refresh_dyndns_server = socketxx::IP( conf.lookup("dyndns_refresh_server_ip") );
				} catch (socketxx::bad_addr_error) {
					__log__(log_lvl::FATAL, "CONF", logstream << "dyndns_refresh_server_ip : invalid IP");
					return 1;
				}
				try {
					dyndns_slave_key_id = conf.lookup("dyndns_refresh_server_key_id").operator std::string();
				} catch (libconfig::SettingNotFoundException&) {}
			}
			try {
				shutdown_ignore_err = (bool)conf.lookup("shutdown_ignore_err");
			} catch (...) {}
			try {
				std::string fixed_hostname = conf.lookup("fixed_hostname").operator std::string();
				::strncpy(hostname, fixed_hostname.c_str(), sizeof(hostname));
			} catch (...) {}
			try {
				std::string shutdown_at = conf.lookup("shutdown_at");
				time_t t = ::time(NULL);
				struct tm time;
				::gmtime_r(&t, &time);
				char* r = ::strptime(shutdown_at.c_str(), "%H:%M", &time);
				if (r == NULL) 
					__log__(log_lvl::ERROR, "CONF", logstream << "shutdown_at : bad format (should be %H:%M)");
				else {
					time_t shutdown_time = 0;
					struct tm time2 = time;
					shutdown_time = ::mktime(&time2);
					if (shutdown_time <= ::time(NULL))
						time.tm_mday += 1;
					shutdown_time = ::mktime(&time);
					shutdown_iosl_time = start_iosl_time + (shutdown_time - ::time(NULL));
				}
			} catch (...) {}
			try {
				time_t shutdown_in = (int)conf.lookup("shutdown_in_minutes");
				shutdown_iosl_time = ::iosl_time() + shutdown_in*60;
			} catch (...) {}
			if (shutdown_iosl_time != 0) 
				__log__(log_lvl::NOTICE, "SHUTDOWN", logstream << "Slave will try to shutdown in " << (shutdown_iosl_time-::iosl_time())/60 << " minutes");
			try {
				libconfig::Setting& allowed_services_c = conf.lookup("allowed_api_services");
				allowed_services_c.assertType(libconfig::Setting::TypeArray);
				for (int i = 0; i < allowed_services_c.getLength(); i++) {
					allowed_api_services.insert(
						allowed_services_c[i].operator std::string()
					);
				}
			} catch (libconfig::SettingNotFoundException&) {}
		}
	} catch (libconfig::ParseException& e) {
		__log__(log_lvl::FATAL, "CONF", logstream << "Parse error in configuration file at line " << e.getLine() << " : " << e.getError());
		return 1;
	} catch (libconfig::FileIOException& e) {
		__log__(log_lvl::FATAL, "CONF", logstream << "Can't read configuration file : " << e.what());
		return 1;
	} catch (libconfig::SettingException& e) {
		__log__(log_lvl::FATAL, "CONF", logstream << "Missing/bad setting @" << e.getPath() << " in configuration file");
		return 1;
	}
	
		// Init UPnP
	if (enable_upnp) {
		__log__(log_lvl::IMPORTANT, NULL, logstream << "Initializing UPnP IGD NAT port mapping...");
		try {
			ioslaves::upnpInit();
		} catch (ioslaves::upnpError) { return EXIT_FAILURE; }
	}
		
		// Load services
	__log__(log_lvl::IMPORTANT, NULL, logstream << "Loading services...");
	{
		size_t ext_sz = ::strlen(IOSLAVESD_SERVICE_FILE_EXT);
		size_t ni;
		DIR* services_dir = ::opendir(IOSLAVESD_SERVICE_FILES_DIR);
		if (services_dir == NULL) { __log__(log_lvl::FATAL, "SERVICES", logstream << "Can't open services dir !"); return EXIT_FAILURE; }
		RAII_AT_END_L( ::closedir(services_dir) );
		dirent* dp = NULL;
		while ((dp = ::readdir(services_dir)) != NULL) {
			for (ni = 1; ni <= ext_sz; ni++)
				if (dp->d_name[::strlen(dp->d_name)-ni] != IOSLAVESD_SERVICE_FILE_EXT[ext_sz-ni]) 
					goto __dp_loop_next;
			{
				std::string serv_name = std::string(dp->d_name).substr(0, ::strlen(dp->d_name)-ni+1);
				if (serv_name.empty()) continue;
				FILE* ser_f = ::fopen(_s( IOSLAVESD_SERVICE_FILES_DIR,"/",std::string(dp->d_name) ), "r");
				ioslaves::loadService(serv_name, ser_f);
				::fclose(ser_f);
			}
		__dp_loop_next:
			continue;
		}
	}
	
		// Main listening socket
	__log__(log_lvl::LOG, NULL, logstream << "Starting listening socket...");
	socketxx::simple_socket_server<socketxx::base_netsock,void> serv(socketxx::base_netsock::addr_info(IN_LISTENING_IP,IN_LISTENING_PORT), IN_ACCEPT_MAX_WAITING_CLIENTS, true);
	serv.set_pool_timeout(::timeval(POOL_TIMEOUT));
	if (enable_upnp and ioslavesd_listening_port_open)
		try {
			ioslaves::upnpPort p = {IN_LISTENING_PORT, ioslaves::upnpPort::TCP, IN_LISTENING_PORT, 1, _S("ioslavesd ",hostname)};
			ioslaves::upnpOpenPort(p);
		} catch (ioslaves::upnpError& ue) {
			__log__(log_lvl::FATAL, "NET", "Can't open port on gateway for listening socket !");
			return EXIT_FAILURE;
		}
	__log__(log_lvl::DONE, "NET", logstream << "ioslavesd slave '" << hostname << "' is listening on port " << IN_LISTENING_PORT);
	
		// Launch port thread
	r = ::pthread_create(&port_thread_handle, NULL, port_thread, NULL);
	if (r != 0)
		throw xif::sys_error("failed to create port thread", r);
	
		// Create stop pipe
	r = ::pipe(serv_stop_pipe);
	if (r == SOCKET_ERROR) throw xif::sys_error("pipe() failed", false);
	
		// Launch status thread
	r = ::pthread_create(&status_thread_handle, NULL, status_thread, NULL);
	if (r != 0)
		throw xif::sys_error("failed to create status thread", r);
	
		// Main event loop
	for (;;) {
	_abort_connect:
		try {
			// Waiting for new client
			socketxx::simple_socket_server<socketxx::base_netsock,void>::client cli = serv.wait_new_client_stoppable(serv_stop_pipe[0], true);
		#ifdef SO_NOSIGPIPE
			cli._setopt_sock_bool(cli.get_fd(), SO_NOSIGPIPE, true);
		#endif
			cli.set_read_timeout(::timeval(IN_CLIENT_TIMEOUT));
			
				// Really ? Are you sure ? Do you really want to disturb the powefull, scarry one, only one, THE SLAVE ?
			bool really = cli.i_bool();
			if (not really) continue;
			ioslaves::op_code opcode;
			
			std::string master_id = cli.i_str();
			if (not master_id.empty() and not ioslaves::validateMasterID(master_id)) {
				__log__(log_lvl::NOTICE, NULL, logstream << cli.addr.get_ip_str() << " : Invalid master ID");
				continue;
			}
			bool auth = cli.i_bool();
			ioslaves::perms_t perms;
			bool silent = false;
			
				// Connection delay refusal
			if (conn_next_delay.find(cli.addr.get_ip_addr().s_addr) != conn_next_delay.end()) {
				time_t next_accept_time = conn_next_delay[cli.addr.get_ip_addr().s_addr];
				if (next_accept_time > ::iosl_time()) {
					if (auth) {
						if (::iosl_time() - next_accept_time > IOSL_CLI_DELAY_REST_TRY) 
							continue;
					} else 
						continue;
				}
			}
			
				// Authentification
			if (auth and not master_id.empty()) {
				ioslaves::key_t key;
				try {
					std::tie (key,perms) = ioslaves::load_master_key(master_id);
					cli.o_char((char)ioslaves::answer_code::OK);
				} catch (ioslaves::req_err& e) {
					__log__(log_lvl::ERROR, "KEY", logstream << "Authentification of " << cli.addr.get_ip_str() << " : Key loading failed : " << e.descr);
					cli.o_char((char)e.answ_code);
					continue;
				}
				unsigned char* challenge = ioslaves::generate_random(CHALLENGE_LEN);
				RAII_AT_END({ delete[] challenge; });
				cli.o_buf(challenge, CHALLENGE_LEN);
				unsigned char buf [CHALLENGE_LEN+KEY_LEN];
				::memcpy(buf, challenge, CHALLENGE_LEN);
				::memcpy(buf+CHALLENGE_LEN, key.bin, KEY_LEN);
				ioslaves::hash_t expected_answer;
				::WHIRLPOOL(buf, CHALLENGE_LEN+KEY_LEN, expected_answer.bin);
				cli.set_read_timeout(IN_CLIENT_AUTH_TIMEOUT);
				ioslaves::hash_t master_answer;
				cli.i_buf(master_answer.bin, HASH_LEN);
				cli.set_read_timeout(IN_CLIENT_TIMEOUT);
				for (size_t i = 0; i < HASH_LEN; i++) {
					if (expected_answer.bin[i] != master_answer.bin[i]) {
						cli.o_char((char)ioslaves::answer_code::BAD_CHALLENGE_ANSWER);
						__log__(log_lvl::NOTICE, "AUTH", logstream << "Authentification failed for " << cli.addr.get_ip_str() << " as '" << master_id << "' ! Bad answer to challenge.");
						conn_next_delay[cli.addr.get_ip_addr().s_addr] = ::iosl_time() + IOSL_CLI_DELAY_FAIL_AUTH;
						goto _abort_connect;
					}
				}
				cli.o_char((char)ioslaves::answer_code::OK);
				opcode = (ioslaves::op_code)cli.i_char();
				silent = ioslaves::perms_verify_op(perms, opcode).props["silent"] == "true";
				if (not silent)
					__log__(log_lvl::LOG, "AUTH", logstream << "Authentification succeeded for '" << master_id << "' (" << cli.addr.get_ip_str() << ")");
				conn_next_delay[cli.addr.get_ip_addr().s_addr] = ::iosl_time() + IOSL_CLI_DELAY_AUTH;
			} else {
				__log__(log_lvl::LOG, "AUTH", logstream << "Connection of " << cli.addr.get_ip_str() << " as " << (master_id.empty() ? "anonymous" : _S("'",master_id,"' (not verified, no auth)")));
				perms.by_default = false;
				opcode = (ioslaves::op_code)cli.i_char();
				conn_next_delay[cli.addr.get_ip_addr().s_addr] = ::iosl_time() + IOSL_CLI_DELAY_NO_AUTH;
			}
			ioslaves::perms_t::op_perm_t op_perms = ioslaves::perms_verify_op(perms, opcode);
			auto OpPermsCheck = [&] () {
				if (not op_perms.authorized) 
					throw ioslaves::req_err(ioslaves::answer_code::NOT_AUTHORIZED, "PERMS", "Permissions are not satisfied for this operation.");
			};
			
				// Query
			try {
				switch (opcode) {
						/** ---------------------- Authorize and send key ---------------------- **/
					case ioslaves::op_code::KEY_AUTH: {
						__log__(log_lvl::LOG, "OP", logstream << "Operation : Key sending authorization");
						std::string footprint = cli.i_str();
						std::string keyperms = cli.i_str();
						std::string auth_master = cli.i_str();
						std::string auth_ip_str = cli.i_str();
						if (auth)
							OpPermsCheck();
						else {
							DIR* dir = ::opendir(IOSLAVESD_KEYS_DIR);
							if (dir == NULL) 
								throw xif::sys_error("can't open keys dir");
							dirent* dp, *dentr = (dirent*) ::malloc((size_t)offsetof(struct dirent, d_name) + std::max(sizeof(dirent::d_name), (size_t)::fpathconf(dirfd(dir),_PC_NAME_MAX)) +1);
							RAII_AT_END({ ::closedir(dir); ::free(dentr); });
							int rr;
							while ((rr = ::readdir_r(dir, dentr, &dp)) != -1 and dp != NULL) {
								if (dentr->d_type != DT_DIR) 
									throw ioslaves::req_err(ioslaves::answer_code::NOT_AUTHORIZED, "PERMS", "Key folder not empty : first key sending can't be satisfied");
							}
							if (rr == -1) throw xif::sys_error("readdir error while listing keys dir");
							__log__(log_lvl::IMPORTANT, "PERMS", logstream << "Master is not authenticated but key folder is empty : authorizing first key sending");
						}
						in_addr_t auth_ip;
						if (not auth_ip_str.empty()) {
							r = ::inet_pton(AF_INET, auth_ip_str.c_str(), &auth_ip);
							if (r != 1) 
								throw ioslaves::req_err(ioslaves::answer_code::INVALID_DATA, "KEY", "Invalid sender master IP");
						}
						if (not ioslaves::validateMasterID(auth_master))
							throw ioslaves::req_err(ioslaves::answer_code::INVALID_DATA, "KEY", "Invalid sender master ID");
						if (footprint.length() != 32 or not ioslaves::validateHexa(footprint))
							throw ioslaves::req_err(ioslaves::answer_code::INVALID_DATA, "KEY", "Invalid key footprint");
						try {
							libconfig::Config test_c;
							test_c.readString(keyperms);
							bool def = test_c.getRoot()["allow_by_default"];
							__log__(log_lvl::IMPORTANT, "KEY", logstream << "Master '" << master_id << "' allows sending of key " << footprint << " in favor of master '" << auth_master << "' with default " << (def?"allowing":"denying") << " permissions for " << IOSLAVES_KEY_SEND_DELAY << "s");
						} catch (libconfig::ConfigException&) {
							throw ioslaves::req_err(ioslaves::answer_code::INVALID_DATA, "KEY", "Invalid permissions settings");
						}
							// Waiting for the key sender master
						serv.set_pool_timeout(timeval({IOSLAVES_KEY_SEND_DELAY,0}));
						RAII_AT_END({
							serv.set_pool_timeout(::timeval(POOL_TIMEOUT));
						});
						cli.o_char((char)ioslaves::answer_code::OK);
						try {
							__log__(log_lvl::LOG, NULL, logstream << "Waiting for sender master connection...");
							decltype(serv)::client clikey = serv.wait_new_client_timeout();
							bool really = clikey.i_bool();
							if (really) 
								throw ioslaves::req_err(ioslaves::answer_code::DENY, NULL, "Normal connection occured while waiting for key sender");
							__log__(log_lvl::LOG, "KEY", "Sender master connected");
							std::string of_master = clikey.i_str();
							if (of_master != auth_master or not (auth_ip_str.empty() or clikey.addr.get_ip_addr().s_addr == auth_ip)) {
								clikey.o_char((char)ioslaves::answer_code::DENY);
								throw ioslaves::req_err(ioslaves::answer_code::DENY, NULL, logstream << "Sender master '" << of_master << "' (" << clikey.addr.get_ip_str() << ") is not authorized master '" << auth_master << "'" << (auth_ip_str.empty()?"":_S( '(',auth_ip_str,')' )));
							}
							ioslaves::key_t key;
							clikey.i_buf(key.bin, KEY_LEN);
							unsigned char hash[MD5_DIGEST_LENGTH];
							::MD5(key.bin, KEY_LEN, hash);
							std::string slave_footprint = ioslaves::bin_to_hex(hash, MD5_DIGEST_LENGTH);
							if (slave_footprint != footprint) {
								clikey.o_char((char)ioslaves::answer_code::DENY);
								throw ioslaves::req_err(ioslaves::answer_code::DENY, NULL, logstream << "Sent key's footprint (" << slave_footprint << ") does not corresponds to the authorized footprint (" << footprint << ")");
							}
							__log__(log_lvl::IMPORTANT, "KEY", logstream << "Key with footprint " << footprint << " is accepted for master " << of_master << " (" << clikey.addr.get_ip_str() << ")");
							ioslaves::key_save(of_master, 
													 key, 
													 keyperms);
							clikey.o_char((char)ioslaves::answer_code::OK);
							cli.o_char((char)ioslaves::answer_code::OK);
							clikey.o_str(keyperms);
							cli.o_str(clikey.addr.get_ip_str());
							__log__(log_lvl::MAJOR, "KEY", logstream << "Master '" << of_master << "' with key '" << slave_footprint << "' now have the following permissions : \n" << keyperms << "\n");
						} catch (socketxx::timeout_event&) {
							throw ioslaves::req_err(ioslaves::answer_code::TIMEOUT, NULL, "Delay expired for key sending !");
						} catch (socketxx::classic_error& e) {
							throw ioslaves::req_err(ioslaves::answer_code::EXTERNAL_ERROR, NULL, "Communication error occured with master while receiving key !");
						}
					} break;
						/** ---------------------- Revoke key ---------------------- **/
					case ioslaves::op_code::KEY_DEL: {
						std::string of_master = cli.i_str();
						__log__(log_lvl::IMPORTANT, "OP", logstream << "Operation : Delete key of master '" << of_master << "'");
						OpPermsCheck();
						r = ::unlink( _s( IOSLAVESD_KEYS_DIR,'/',of_master,".key" ) );
						if (r == -1) {
							if (errno == ENOENT) 
								throw ioslaves::req_err(ioslaves::answer_code::NOT_FOUND, "KEY", "Key not found !");
							else 
								throw xif::sys_error("can't delete key");
						}
						__log__(log_lvl::MAJOR, "KEY", logstream << "Key of master '" << of_master << "' is revoked");
					} break;
						/** ---------------------- Start/Stop service ---------------------- **/
					case ioslaves::op_code::SERVICE_START: 
					case ioslaves::op_code::SERVICE_STOP: {
						bool start = opcode == ioslaves::op_code::SERVICE_START;
						__log__(log_lvl::LOG, "OP", logstream << "Operation : " << (start?"Start":"Stop") << " service", silent& LOG_DEBUG);
						std::string service = cli.i_str();
						OpPermsCheck();
						bool bydefault = (op_perms.props.find("*default*") == op_perms.props.end()) ? (perms.by_default) 
						                                                                            : (op_perms.props["*default*"] == "true" or false);
						bool allow;
						     if (op_perms.props[service] == "true")  allow = true;
						else if (op_perms.props[service] == "false") allow = false;
						else                                         allow = bydefault;
						if (not allow) 
							throw ioslaves::req_err(ioslaves::answer_code::NOT_AUTHORIZED, "PERMS", logstream << "Permissions are not satisfied to manage service '" << service << "'");
						ioslaves::controlService( ioslaves::getServiceByName(service), 
						                          (bool)start, 
						                          master_id.c_str());
					} break;
						/** ---------------------- Open/Close port ---------------------- **/
					case ioslaves::op_code::IGD_PORT_OPEN:
					case ioslaves::op_code::IGD_PORT_CLOSE: {
						std::string descr;
						if (opcode == ioslaves::op_code::IGD_PORT_OPEN) {
							__log__(log_lvl::LOG, "OP", "Operation : Open port on IGD", silent& LOG_DEBUG);
							descr = cli.i_str();
						} else {
							__log__(log_lvl::LOG, "OP", "Operation : Close port on IGD", silent& LOG_DEBUG);
						}
						char type = cli.i_char();
						ioslaves::upnpPort::proto proto;
						bool range = false;
						switch (type) {
							case 't': proto = ioslaves::upnpPort::TCP; range = false; break;
							case 'T': proto = ioslaves::upnpPort::TCP; range = true; break;
							case 'u': proto = ioslaves::upnpPort::UDP; range = false; break;
							case 'U': proto = ioslaves::upnpPort::UDP; range = true; break;
							default: throw ioslaves::req_err(ioslaves::answer_code::INVALID_DATA, "UPnP", logstream << "Invalid port type '" << type << "'");
						}
						uint16_t range_sz = 1;
						in_port_t port = cli.i_int<uint16_t>();
						if (range) {
							in_port_t port_end = cli.i_int<uint16_t>();
							if (port_end < port) 
								throw ioslaves::req_err(ioslaves::answer_code::INVALID_DATA, "UPnP", logstream << "Range : End can't be lower than begin");
							range_sz = port_end-port+1;
						}
						OpPermsCheck();
						if (opcode == ioslaves::op_code::IGD_PORT_OPEN) {
							if (enable_upnp) try {
								ioslaves::upnpPort p = {port, proto, port, range_sz, descr};
								if (ioslaves::upnpPortRangeCollision(port, range_sz, p.p_proto)) {
									if (range_sz == 1) throw ioslaves::req_err(ioslaves::answer_code::EXISTS, "UPnP", logstream << "Port " << (char)p.p_proto << port << " is already opened");
									else throw ioslaves::req_err(ioslaves::answer_code::EXISTS, "UPnP", logstream << "Port range is in collision with another port(s)");
								}
								ioslaves::upnpOpenPort(p);
							} catch (ioslaves::upnpError& upnperr) {
								if (not upnperr.fatal) {
									cli.o_char((char)ioslaves::answer_code::MAY_HAVE_FAIL);
									continue;
								}
								throw ioslaves::req_err(ioslaves::answer_code::ERROR,  "UPnP", logstream << "Error while closing port : " << upnperr.what());
							}
						} else {
							if (port == IN_LISTENING_PORT) 
								throw ioslaves::req_err(ioslaves::answer_code::DENY, "UPnP", logstream << "Can't close port " << port << " : used by ioslavesd");
							if (enable_upnp) try {
								if (not ioslaves::upnpPortRangeExists(ioslaves::upnpPort({port, proto, port, range_sz})))
									throw ioslaves::req_err(ioslaves::answer_code::NOT_FOUND, "UPnP", logstream << "Port" << (range_sz==1?"":" range") << " is not in port table");
								ioslaves::upnpPort p = {port, proto, port, range_sz};
								ioslaves::upnpClosePort(p);
							} catch (ioslaves::upnpError& upnperr) {
								throw ioslaves::req_err(ioslaves::answer_code::ERROR, "UPnP", logstream << "Error while closing port : " << upnperr.what());
							}
						}
					} break;
						/** ---------------------- Status ---------------------- **/
					case ioslaves::op_code::GET_STATUS: {
						__log__(log_lvl::LOG, "OP", "Operation : Get status", silent& LOG_DEBUG);
						xif::polyvar infos = ioslaves::getStatus(true);
						cli.o_var(infos);
					} break;
					case ioslaves::op_code::PERM_STATUS: {
						__log__(log_lvl::LOG, "OP", "Registering to the permanent status pool", silent& LOG_DEBUG);
						pthread_mutex_handle_lock(status_clients_mutex);
						status_clients.insert(status_clients.begin(), cli);
					} break;
						/** ---------------------- Auto-shutdown control ---------------------- **/
					case ioslaves::op_code::SHUTDOWN_CTRL: {
						__log__(log_lvl::LOG, "OP", "Operation : change auto-shutdown time", silent& LOG_DEBUG);
						time_t shutdown_in = cli.i_int<uint32_t>();
						OpPermsCheck();
						if (shutdown_in == 0) {
							__log__(log_lvl::IMPORTANT, "SHUTDOWN", "Automatic shutdown disabled");
							shutdown_iosl_time = 0;
						} else {
							__log__(log_lvl::IMPORTANT, "SHUTDOWN", logstream << "Automatic shutdown set in " << shutdown_in/60 << "min");
							shutdown_iosl_time = ::iosl_time() + shutdown_in;
						}
					} break;
						/** ---------------------- Shutdown/Reboot ---------------------- **/
					case ioslaves::op_code::SLAVE_SHUTDOWN:
					case ioslaves::op_code::SLAVE_REBOOT: {
						bool does_reboot = (opcode == ioslaves::op_code::SLAVE_REBOOT);
						__log__(log_lvl::MAJOR, "OP", logstream << "Operation : " << (does_reboot ? "Rebooting" : "Shutting down") << " server NOW !");
						OpPermsCheck();
						quit_type = does_reboot ? QUIT_REBOOT : QUIT_SHUTDOWN;
						cli.o_char((char)ioslaves::answer_code::OK);
						throw socketxx::stop_event(0);
					} break;
						/** ---------------------- API Service connection ---------------------- **/
					case ioslaves::op_code::CALL_API_SERVICE: {
						std::string service_name = cli.i_str();
						__log__(log_lvl::LOG, "OP", logstream << "Operation : Calling API service '" << service_name << "'", silent& LOG_DEBUG);
						if (auth)
							OpPermsCheck();
						bool bydefault = (op_perms.props.find("*default*") == op_perms.props.end()) ? (perms.by_default) 
						                                                                            : (op_perms.props["*default*"] == "true" or false);
						bool allow;
						     if (op_perms.props[service_name] == "true")  allow = true;
						else if (op_perms.props[service_name] == "false") allow = false;
						else                                              allow = bydefault;
						if (not allow and allowed_api_services.find(service_name) == allowed_api_services.end()) 
							throw ioslaves::req_err(ioslaves::answer_code::NOT_AUTHORIZED, "PERMS", logstream << "Permissions are not satisfied to connect to API service '" << service_name << "'");
						ioslaves::api::api_perm_t api_perms;
						api_perms.by_default = perms.by_default;
						for (auto p : op_perms.props) {
							if (p.first.find(service_name+'*') == 0) {
								std::string prop = p.first.substr(service_name.length()+1);
								if (prop == "*default*") 
									api_perms.by_default = p.second == "true" or false;
								else 
									api_perms.props.insert({ prop, p.second });
							}
						}
						ioslaves::service* service = ioslaves::getServiceByName(service_name);
						if (service->s_type != ioslaves::service::type::IOSLPLUGIN) 
							throw ioslaves::req_err(ioslaves::answer_code::BAD_TYPE, "OP", logstream << "Service '" << service_name << "' is not an API service");
						if (service->ss_status_running == false) 
							throw ioslaves::req_err(ioslaves::answer_code::BAD_STATE, "OP", logstream << "API service '" << service_name << "' not running");
						dl_t dl_handle = service->spec.plugin.handle;
	__extension__	ioslaves::api::net_client_call_f cli_call_f = (ioslaves::api::net_client_call_f) ::dlsym(dl_handle, "ioslapi_net_client_call");
						if (cli_call_f == NULL) 
							throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "API", logstream << "Error getting function with dlsym(\"ioslapi_net_client_call\") : " << ::dlerror());
						cli.o_char((char)ioslaves::answer_code::OK);
						try {
							(*cli_call_f)(cli, master_id.c_str(), (auth ? &api_perms : NULL), cli.addr.get_ip_addr().s_addr);
							ioslaves::api::euid_switch(-1,-1);
						} catch (ioslaves::req_err& e) {
							throw;
						} catch (std::exception& e) {
							throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "API", logstream << "Error in ioslapi_net_client_call: " << e.what());
						}
						continue;
					}
						/** ---------------------- Log ---------------------- **/
					case ioslaves::op_code::LOG_HISTORY: {
						__log__(log_lvl::LOG, "OP", logstream << "Operation : Get log history", LOG_WAIT, &l);
						time_t log_begin = cli.i_int<int64_t>();
						time_t log_end = cli.i_int<int64_t>();
						OpPermsCheck();
						__log__(log_lvl::LOG, "OP", logstream << "from " << log_begin << " to " << (log_end==0?"end":ixtoa(log_end)), LOG_WAIT|LOG_ADD, &l);
						size_t i, beg = 0, end = log_history.size();
						if (log_begin != 0) {
							for (i = 0; i < log_history.size(); i++) 
								if (log_history[i].le_time >= log_begin) { beg = i; goto _log_seek_end; }
							cli.o_int<uint64_t>(0);
							break;
						}
					_log_seek_end:
						if (log_end != 0 and log_end >= log_begin) {
							for (; i < log_history.size(); i++) 
								if (log_end > log_history[i].le_time) { end = i+1; goto _log_send; }
						}
						if (log_begin > log_end) { beg = 0; end = 0; }
					_log_send:
						__log__(log_lvl::LOG, "OP", logstream << "(" << (end-beg) << " lines)", LOG_ADD, &l);
						cli.o_int<uint64_t>(end-beg);
						for (i = beg; i < end; i++) {
							cli.o_int<uint64_t>(log_history[i].le_time);
							cli.o_char((char)log_history[i].le_lvl);
							cli.o_str((log_history[i].le_part==NULL)?"":log_history[i].le_part);
							cli.o_str(log_history[i].le_msg);
						}
					} break;
					default:
						__log__(log_lvl::NOTICE, "OP", logstream << "Unknown opcode '" << (char)opcode << "'");
						cli.o_char((char)ioslaves::answer_code::OP_NOT_DEF);
						continue;
				}
				cli.o_char((char)ioslaves::answer_code::OK);
			} catch (ioslaves::req_err& e) {
				cli.o_char((char)e.answ_code);
			} catch (xif::sys_error& e) {
				cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR);
				throw;
			}
		
			// Net error
		} catch (socketxx::error& se) {
			__log__(log_lvl::OOPS, "NET", logstream << "Communication error with client : " << se.what());
			continue;
		}
			// System error
		catch (xif::sys_error& e) {
			__log__(log_lvl::ERROR, NULL, logstream << "Catched system error : " << e.what());
			continue;
		}
			// Scheduled timeout
		catch (socketxx::timeout_event&) {
			
				// Contact XifNet DynDNS server to refresh public IP
			if (ip_refresh_dyndns_interval >= 0) {
				static time_t dyndns_last = 0;
				if (dyndns_last+ip_refresh_dyndns_interval < ::time(NULL)) {
					dyndns_last = ::time(NULL);
					static in_addr_t my_ip_last = 0;
					if (my_ip_last == 0) {
						std::string key_path = _S( IOSLAVES_MASTER_KEYS_DIR,'/',dyndns_slave_key_id,".key" );
						r = ::access(key_path.c_str(), R_OK);
						if (r == -1) 
							__log__(log_lvl::WARNING, "DynDNS", logstream << "No key " << key_path << " available for DynDNS slave : " << ::strerror(errno));
					} else 
						iosl_master::$silent = true;
					try {
						iosl_master::$leave_exceptions = true;
						RAII_AT_END({ iosl_master::$leave_exceptions = false; iosl_master::$silent = false; });
						socketxx::simple_socket_client<socketxx::base_netsock> sock (socketxx::base_netsock::addr_info(ip_refresh_dyndns_server, 2929), timeval{1,0});
						sock.set_read_timeout(timeval{0,800000});
						if (r == 0)
							iosl_master::slave_command_auth(sock, _S("_IOSL_",hostname), ioslaves::op_code::CALL_API_SERVICE, dyndns_slave_key_id);
						else 
							iosl_master::slave_command(sock, _S("_IOSL_",hostname), ioslaves::op_code::CALL_API_SERVICE);
						sock.o_str("xifnetdyndns");
						ioslaves::answer_code answ = (ioslaves::answer_code)sock.i_char();
						if (answ != ioslaves::answer_code::OK) 
							throw answ;
						sock.o_int<in_port_t>(ioslavesd_listening_port);
						in_addr_t my_ip = sock.i_int<in_addr_t>();
						if (my_ip_last == 0) 
							__log__(log_lvl::MAJOR, "DynDNS", logstream << "Public IP is " << socketxx::base_netsock::addr_info::addr2str(my_ip));
						else if (my_ip_last != my_ip) 
							__log__(log_lvl::MAJOR, "DynDNS", logstream << "Public IP changed from " << socketxx::base_netsock::addr_info::addr2str(my_ip_last) << " to " << socketxx::base_netsock::addr_info::addr2str(my_ip));
						my_ip_last = my_ip;
						if ((answ = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) {
							__log__(log_lvl::ERROR, "DynDNS", logstream << "Refresh IP failed : " << ioslaves::getAnswerCodeDescription(answ));
							continue;
						}
						sock.o_char((char)ioslaves::answer_code::OK);
					} catch (socketxx::classic_error& e) {
						log_lvl lvl = (e.get_errno()==EAGAIN) ? log_lvl::OOPS : log_lvl::ERROR;
						__log__(lvl, "DynDNS", logstream << "Network error with xifnetdyndns service : " << e.what(), lvl==log_lvl::OOPS?LOG_DEBUG:0);
					} catch (master_err& e) {
						__log__(log_lvl::ERROR, "DynDNS", logstream << "Master error while connecting to DynDNS : " << e.what());
					} catch (ioslaves::answer_code answ) {
						__log__(log_lvl::ERROR, "DynDNS", logstream << "DynDNS service error : " << ioslaves::getAnswerCodeDescription(answ));
					}
				}
			}
			
				// Auto shutdown
			if (shutdown_iosl_time != 0) {
				static time_t last_shutdown_chk = ::iosl_time();
				if (last_shutdown_chk + IOSL_SHUTDOWN_CHK_INTERVAL < ::iosl_time()) {
					last_shutdown_chk = ::iosl_time();
					if (::iosl_time() > shutdown_iosl_time) {
						__log__(log_lvl::IMPORTANT, "SHUTDOWN", logstream << "Slave will now try to shut down !");
						for (ioslaves::service* s : ioslaves::services_list) {
							if (s->ss_shutdown_inhibit and s->ss_status_running) {
								if (s->s_type == ioslaves::service::type::IOSLPLUGIN) {
									dl_t dl_handle = s->spec.plugin.handle;
				__extension__ 	ioslaves::api::shutdown_inhibit_f inhib_f = (ioslaves::api::shutdown_inhibit_f) ::dlsym(dl_handle, "ioslapi_shutdown_inhibit");
									if (inhib_f == NULL) {
										__log__(log_lvl::WARNING, "SHUTDOWN", logstream << "Can't get ioslapi_shutdown_inhibit function of ioslplugin '" << s->s_name << "' : " << ::dlerror());
										continue;
									}
									try {
										bool inhib = (*inhib_f)();
										ioslaves::api::euid_switch(-1,-1);
										if (not inhib) 
											continue;
									} catch (std::exception& e) {
										__log__(log_lvl::ERROR, "API", logstream << "Error in ioslapi_shutdown_inhibit for '" << s->s_name << "' : " << e.what());
										continue;
									}
								}
								__log__(log_lvl::IMPORTANT, "SHUTDOWN", logstream << "Shutdown inhibited by service '" << s->s_name << "'");
								goto __inhibit;
							}
						}
						__log__(log_lvl::MAJOR, "SHUTDOWN", logstream << "Shutting down slave NOW !");
						quit_type = QUIT_SHUTDOWN;
						break;
					__inhibit:;
					} else if (::iosl_time()+3600 > shutdown_iosl_time) 
						__log__(log_lvl::NOTICE, "SHUTDOWN", logstream << "Slave will try to shut down in " << (shutdown_iosl_time-::iosl_time())/60 << " minutes");
				}
			}
			
			continue;
		} 
			// Stop from signals_thread
		catch (socketxx::stop_event&) {
			break;
		}
		
		continue;
	}
	
		// Stop services
	ioslaves::stopAllServices();
	for (ioslaves::service* s : ioslaves::services_list) {
		delete s;
	}
	
		// Save stats
	ioslaves::statusEnd();
	
		// Stop sched threads
	::sched_threads_run = false;
	::pthread_join(status_thread_handle, NULL);
	::pthread_join(port_thread_handle, NULL);
	
	} catch (std::exception& e) {
		__log__(log_lvl::FATAL, NULL, logstream << "Exception of type '" << typeid(e).name() << "' catched : " << e.what());
		return EXIT_FAILURE;
	}
	
	if (quit_type != QUIT_NORMAL) {
		*signal_catch_sigchild_p = false;
		ioslaves::api::euid_switch(0,0);
		r = ::system( _s("shutdown -",(quit_type==QUIT_REBOOT?'r':'h')," now") ); 
	}
	
	__log__(log_lvl::MAJOR, NULL, "-=# Exiting... #=-");
	::exit(EXIT_SUCCESS);
}

	/// Status thread
void* status_thread (void*) {
	
		// Block signals
	thread_block_signals();
	
	try {
		
		while (::sched_threads_run) {
			::usleep(1000000);
			
				// Topp frame
			ioslaves::statusFrame();
			
				// Permanent status
			pthread_mutex_handle_lock(status_clients_mutex);
			if (status_clients.size() != 0) {
				xif::polyvar infos = ioslaves::system_stat;
				infos["me"] = hostname;
				for (auto it = status_clients.begin(); it != status_clients.end();) {
					try {
						(*it).o_var(infos);
						++it;
					} catch (socketxx::error& e) {
						__log__(log_lvl::NOTICE, "NET", logstream << "Erasing client from the status pool : " << e.what());
						auto p_it = it++; status_clients.erase(p_it);
					}
				}
			}
			
		}
		__log__(log_lvl::LOG, "THREAD", logstream << "Ejecting status clients and quit status thread", LOG_DEBUG);
		
			// Eject permanant status clients
		pthread_mutex_handle_lock(status_clients_mutex);
		while (status_clients.size()) 
			status_clients.erase(status_clients.begin());
		
	} catch (std::exception& e) {
		__log__(log_lvl::FATAL, NULL, logstream << "Exception catched in status thread : " << e.what());
		::exit(EXIT_FAILURE);
	}
	
	return NULL;
}

	/// Port reopen thread
void* port_thread (void*) {
	
		// Block signals
	thread_block_signals();
	
	try {
		
		while (::sched_threads_run) {
			::sleep(1);
				// Check and reopen ports
			if (enable_upnp)
				ioslaves::upnpReopen();
		}
		__log__(log_lvl::LOG, "THREAD", logstream << "Closing remaining ports and quit port thread", LOG_DEBUG);
		
			// Close remaining ports
		try {
			if (enable_upnp and ioslavesd_listening_port_open)
				ioslaves::upnpClosePort(ioslaves::upnpPort({IN_LISTENING_PORT, ioslaves::upnpPort::TCP, IN_LISTENING_PORT, 1}));
			ioslaves::upnpShutdown();
		} catch (...) {}
		
	} catch (std::exception& e) {
		__log__(log_lvl::FATAL, NULL, logstream << "Exception catched in status thread : " << e.what());
		::exit(EXIT_FAILURE);
	}
	
	return NULL;
}

	/// Signals thread
void _stop_serv (int);
void _sigchild (int);
fd_t _sig_pipe[2] = {INVALID_HANDLE,INVALID_HANDLE};
void* signals_thread (void* _data) {
	
		// Create signal pipe
	int r = ::pipe(_sig_pipe);
	if (r == SOCKET_ERROR) throw xif::sys_error("signals : pipe() failed", false);
	
		// Block signals : this thread will NOT execute signal handler.
		// Others threads than main shall not execute ::system()
	sigset_t sigs_main_blocked;
	sigemptyset(&sigs_main_blocked);
	for (size_t si = 0; sigs_to_block[si] != (int)NULL; ++si)
		sigaddset(&sigs_main_blocked, sigs_to_block[si]);
	::pthread_sigmask(SIG_BLOCK, &sigs_main_blocked, NULL);
	
		// Attach stop signals to `stop(int)` function
	struct sigaction sigs_action;
	sigs_action.sa_handler = &_stop_serv;
	sigemptyset(&sigs_action.sa_mask);
	sigs_action.sa_flags = SA_RESTART;
	int sigs_to_block[] = { SIGINT, SIGQUIT, SIGHUP, SIGTERM, (int)NULL };
	for (size_t si = 0; sigs_to_block[si] != (int)NULL; ++si)
		::sigaction(sigs_to_block[si], &sigs_action, NULL);
	
		// SIGCHILD, special treatment
	struct sigaction sigchild_action;
	sigchild_action.sa_handler = &_sigchild;
	sigemptyset(&sigchild_action.sa_mask);
	sigchild_action.sa_flags = SA_RESTART;
	::sigaction(SIGCHLD, &sigchild_action, NULL);
	
		// Loop
	for (;;) {
		
		/* sigwait() = plus simple */
		
		char c;
		ssize_t rs = ::read(_sig_pipe[0], &c, 1);
		if (rs != 1) throw xif::sys_error("signals thread : read code failed");
		
		if (c == 'C') { // SIGCHILD
			pid_t pid;
			int status;
			rs = ::read(_sig_pipe[0], &pid, sizeof(pid_t));
			if (rs != sizeof(pid_t)) throw xif::sys_error("read(sig_pipe, pid) failed");
			rs = ::read(_sig_pipe[0], &status, sizeof(int));
			if (rs != sizeof(int)) throw xif::sys_error("read(sig_pipe, status) failed");
			__log__(log_lvl::LOG, NULL, logstream << "Catched SIGCHILD for pid° " << pid);
			for (const ioslaves::service* s : ioslaves::services_list) {
				if (s->s_type != ioslaves::service::type::IOSLPLUGIN) continue;
				if (not s->ss_status_running) continue;
				dl_t dl_handle = s->spec.plugin.handle;
				__extension__	ioslaves::api::got_sigchld_f sig_call_f = (ioslaves::api::got_sigchld_f) ::dlsym(dl_handle, "ioslapi_got_sigchld");
				if (sig_call_f == NULL) 
					__log__(log_lvl::WARNING, "API", logstream << "Can't get function `ioslapi_got_sigchld` for service " << s->s_name);
				else try {
					bool own = (*sig_call_f)(pid, status);
					if (own) break;
				} catch (std::exception& e) {
					__log__(log_lvl::ERROR, "API", logstream << "Error in ioslapi_got_sigchld for '" << s->s_name << "' : " << e.what());
				}
			}
		}
		else if (c == 'S') { // SIG{INT,QUIT,HUP,TERM}
			if (serv_stop_pipe[1] == INVALID_HANDLE) 
				::exit(EXIT_FAILURE);
			rs = ::write(serv_stop_pipe[1], "", 1);
			if (rs != 1) throw xif::sys_error("signals thread : write stop byte failed");
		}
		else ::abort();
		
	}
	
}
void _stop_serv (int param) {
	if (::isatty(STDOUT_FILENO))
		::fputc('\n', stdout);
	ssize_t rs = ::write(_sig_pipe[1], "S", 1);
	if (rs < 1) ::abort();
}
void _sigchild (int param) {
	if (not *signal_catch_sigchild_p) return;
	int status;
	pid_t pid = ::waitpid((pid_t)-1, &status, WUNTRACED|WNOHANG);
	if (pid == -1) return;
	unsigned char buf[1+sizeof(pid_t)+sizeof(int)] = { 'C',0 };
	::memcpy(buf+1,               &pid,    sizeof(pid_t));
	::memcpy(buf+1+sizeof(pid_t), &status, sizeof(int));
	ssize_t rs = ::write(_sig_pipe[1], buf, sizeof(buf));
	if (rs != sizeof(buf)) throw xif::sys_error("write(sig_pipe, child info) failed");
}

	///-----------------  API callbacks  -----------------///

/// Log
void ioslaves::api::report_log (ioslaves::service* _service, log_lvl _lvl, const char* _part, std::string& _msg, int _m, logl_t* _lid) noexcept {
	std::string partstr = _S("API:", _service->s_name, ((_part == NULL) ? std::string() : _S("] [", _part)));
	char* part = new char[partstr.length()+1]; // Leak, but log history is kept until exit
	::strcpy(part, partstr.c_str());
	return __log__(_lvl, part, _msg, _m, _lid);
}

/// SRV entry requests
	// Common
constexpr timeval dnssrvreq_timeout = ::timeval{2,500000};
ioslaves::answer_code ioslaves::dns_srv_req (std::function< ioslaves::answer_code(socketxx::io::simple_socket<socketxx::base_netsock>&) > reqf) {
	try {
		socketxx::simple_socket_client<socketxx::base_netsock> sock (socketxx::base_netsock::addr_info(ip_refresh_dyndns_server, 2929), dnssrvreq_timeout);
		sock.set_read_timeout(dnssrvreq_timeout);
		iosl_master::slave_command_auth(sock, _S("_IOSL_",hostname), ioslaves::op_code::CALL_API_SERVICE, dyndns_slave_key_id);
		sock.o_str("xifnetdyndns");
		ioslaves::answer_code answ = (ioslaves::answer_code)sock.i_char();
		if (answ != ioslaves::answer_code::OK) 
			throw answ;
		sock.o_int<in_port_t>(0);
		sock.i_int<in_addr_t>();
		sock.o_char((char)ioslaves::answer_code::WANT_SEND);
		ioslaves::answer_code o = reqf(sock);
		return o;
	} catch (socketxx::classic_error& e) {
		__log__(log_lvl::ERROR, "DynDNS", logstream << "Network error with xifnetdyndns service : " << e.what());
	} catch (master_err& e) {
		__log__(log_lvl::ERROR, "DynDNS", logstream << "Master error while connecting to DynDNS : " << e.what());
	} catch (ioslaves::answer_code answ) {
		__log__(log_lvl::ERROR, "DynDNS", logstream << "Error with xifnetdyndns service : " << ioslaves::getAnswerCodeDescription(answ));
	}
	return ioslaves::answer_code::ERROR;
}
	// Add SRV entry
ioslaves::answer_code ioslaves::api::dns_srv_create (const char* service_name, std::string domain, std::string host, bool with_cname, in_port_t port, bool is_tcp) noexcept {
	return ioslaves::dns_srv_req(
		[&] (socketxx::io::simple_socket<socketxx::base_netsock>& sock) -> ioslaves::answer_code {
			sock.o_bool(true);
			sock.o_str(service_name);
			sock.o_str(domain);
			sock.o_str(host);
			sock.o_bool(with_cname);
			sock.o_bool(is_tcp);
			sock.o_int<in_port_t>(port);
			ioslaves::answer_code answ;
			if ((answ = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) {
				__log__(log_lvl::ERROR, "DynDNS", logstream << "Failed to create SRV entry : " << ioslaves::getAnswerCodeDescription(answ));
				return answ;
			}
			sock.o_char((char)ioslaves::answer_code::OK);
			return ioslaves::answer_code::OK;
		}
	);
}
	// Delete SRV entry
void ioslaves::api::dns_srv_del (const char* service_name, std::string domain, std::string host, bool is_tcp) noexcept {
	ioslaves::dns_srv_req(
		[&] (socketxx::io::simple_socket<socketxx::base_netsock>& sock) -> ioslaves::answer_code {
			sock.o_bool(false);
			sock.o_str(service_name);
			sock.o_str(domain);
			sock.o_str(host);
			sock.o_bool(is_tcp);
			ioslaves::answer_code answ;
			if ((answ = (ioslaves::answer_code)sock.i_char()) != ioslaves::answer_code::OK) {
				__log__(log_lvl::ERROR, "DynDNS", logstream << "Failed to delete SRV entry : " << ioslaves::getAnswerCodeDescription(answ));
				return answ;
			}
			sock.o_char((char)ioslaves::answer_code::OK);
			return ioslaves::answer_code::OK;
		}
	);
}

	///-----------------  Services  -----------------///

#define _IOSLAVES_STR_TO_SERVICE_TYPE(TYPE) if (str == std::string(#TYPE)) return type::TYPE;
ioslaves::service::type ioslaves::service::strToType (std::string str) {
	_IOSLAVES_STR_TO_SERVICE_TYPE(SYSTEMCTL);
	_IOSLAVES_STR_TO_SERVICE_TYPE(PROG_DEAMON);
	_IOSLAVES_STR_TO_SERVICE_TYPE(IOSLPLUGIN);
	throw std::runtime_error(logstream << "service::strToType : Unknown type '" << str << "' in field 'type' !" << logstr);
}
#define _IOSLAVES_SERVICE_TYPE_TO_STR(TYPE) if (this->s_type == type::TYPE) return std::string(#TYPE);
std::string ioslaves::service::typeToStr () {
	_IOSLAVES_SERVICE_TYPE_TO_STR(SYSTEMCTL);
	_IOSLAVES_SERVICE_TYPE_TO_STR(PROG_DEAMON);
	_IOSLAVES_SERVICE_TYPE_TO_STR(IOSLPLUGIN);
	throw std::logic_error("typeToStr: bad service type");
}

	/// Load from file and add service to service list
void ioslaves::loadService (std::string name, FILE* service_file) {
	bool autostart = false;
	ioslaves::service* s = new ioslaves::service;
	s->s_name = name;
	try {
		libconfig::Config service_conf;
		service_conf.read(service_file);
		s->s_type = service::strToType( service_conf.lookup("type").operator std::string() );
		s->s_name = name;
		s->s_command = service_conf.lookup("command").operator std::string();
		std::string port_descr = _S( s->s_name," service on ",hostname );
		if (service_conf.exists("port")) {
			ioslaves::upnpPort p;
			p.p_range_sz = 1;
			p.p_descr = port_descr;
			p.p_ext_port = p.p_int_port = (in_port_t)(unsigned int)service_conf.lookup("port");
			std::string proto = service_conf.lookup("port_proto").operator std::string();
			if (proto == "TCP+UDP") {
				p.p_proto = ioslaves::upnpPort::TCP;
				s->s_ports.push_back(p);
				p.p_proto = ioslaves::upnpPort::UDP;
				s->s_ports.push_back(p);
			} else {
				     if (proto == "TCP") p.p_proto = ioslaves::upnpPort::TCP;
				else if (proto == "UDP") p.p_proto = ioslaves::upnpPort::UDP;
				else 
					throw std::runtime_error("ports : invalid protocol");
				s->s_ports.push_back(p);
			}
		} else if (service_conf.exists("ports")) {
			std::string str = service_conf.lookup("ports").operator std::string();
			if (str[str.length()-1] != ',') str += ',';
			ioslaves::upnpPort p;
			p.p_descr = port_descr;
			std::string num;
			in_port_t portnum;
			enum { PORT_NEW, PORT_NUM } st = PORT_NEW;
			for (size_t i = 0; i < str.length(); i++) {
				if (st == PORT_NEW) {
					p.p_range_sz = 1;
					     if (str[i] == 'T') p.p_proto = ioslaves::upnpPort::TCP;
					else if (str[i] == 'U') p.p_proto = ioslaves::upnpPort::UDP;
					else 
						throw std::runtime_error(logstream << "ports : invalid protocol letter '" << str[i] << "'" << logstr);
					st = PORT_NUM;
					portnum = 0;
					p.p_ext_port = 0;
				} else if (st == PORT_NUM) {
					if (isdigit(str[i]))
						num += str[i];
					else if (str[i] == ',' or str[i] == '-') {
						if (portnum != 0) 
							p.p_ext_port = p.p_int_port = portnum;
						try {
							portnum = ::atoix<uint16_t>(num, IX_DEC);
							num.erase();
							if (portnum == 0) throw std::runtime_error("cannot be 0");
							if (p.p_ext_port != 0) {
								if (portnum <= p.p_ext_port) throw std::runtime_error("second port number in port range must be greater than first");
								p.p_range_sz = portnum-p.p_ext_port+1;
								s->s_ports.push_back(p);
								st = PORT_NEW;
								continue;
							}
							if (str[i] == '-') continue;
							else {
								p.p_ext_port = p.p_int_port = portnum;
								p.p_range_sz = 1;
								s->s_ports.push_back(p);
								st = PORT_NEW;
							}
						} catch (std::runtime_error& e) {
							throw std::runtime_error(_S( "port numer : ",e.what() ));
						}
					} else {
						throw std::runtime_error(logstream << "char '" << str[i] << "' not allowed in port number" << logstr);
					}
				}
			}
		}
			// Autostart
		try {
			autostart = (bool)service_conf.lookup("autostart");
		} catch (libconfig::SettingNotFoundException) {}
		
			// Shutdown inhibit
		s->ss_shutdown_inhibit = (s->s_type == ioslaves::service::type::IOSLPLUGIN);
		try {
			s->ss_shutdown_inhibit = (bool)service_conf.lookup("shutdown_inhibit");
		} catch (libconfig::SettingNotFoundException) {}
		
			// Specific service type params
		switch (s->s_type) {
			case ioslaves::service::type::IOSLPLUGIN:
			case ioslaves::service::type::SYSTEMCTL:
				if (!ioslaves::validateShellProgramName(s->s_command)) {
					__log__(log_lvl::ERROR, "SECURITY", logstream << "Service " << s->s_name << " : `" << s->s_command << "` is not a valid name !");
					return;
				}
				break;
			case ioslaves::service::type::PROG_DEAMON: 
				try {
					std::string pidfile = service_conf.lookup("pid_file").operator std::string();
					s->spec.exec.pid_file = new char[pidfile.length()+1];
					::strcpy(s->spec.exec.pid_file, pidfile.c_str());
				} catch (libconfig::SettingNotFoundException&) {
					__log__(log_lvl::WARNING, "SERVICE", logstream << "Service '" << s->s_name << "' have no PID file defined : will be not stoppable");
				}
				std::string execnam = service_conf.lookup("proc_name").operator std::string();
				s->spec.exec.execnam = new char[execnam.length()+1];
				::strcpy(s->spec.exec.execnam, execnam.c_str());
				break;
		}
	} catch (libconfig::SettingException& e) {
		__log__(log_lvl::ERROR, "SERVICE", logstream << "Skipping service : Missing/bad field @" << e.getPath() << " in description file of service `" << name << "`");
		return;
	} catch (std::exception& e) {
		__log__(log_lvl::ERROR, "SERVICE", logstream << "Skipping service : Error in description file of service `" << name << "` : " << e.what());
		return;
	}
	__log__(log_lvl::LOG, "SERVICE", logstream << "Service '" << s->s_name << "' of type " << s->typeToStr() << " loaded");
	s->ss_last_status_change = (time_t)0;
	s->ss_status_running = false;
	services_list.push_back(s);
	if (autostart) 
		try {
			ioslaves::controlService(s, true, NULL);
		} catch (ioslaves::req_err& re) {
			__log__(log_lvl::ERROR, "SERVICE", logstream << "Autostart service " << s->s_name << " failed !");
		}
}
	// Service destructor
ioslaves::service::~service () { 
	if (this->s_type == type::PROG_DEAMON and this->spec.exec.pid_file != NULL) {
		delete[] this->spec.exec.pid_file;
		delete[] this->spec.exec.execnam;
	}
}

	/// Stop all services
void ioslaves::stopAllServices () {
	__log__(log_lvl::IMPORTANT, "IOSLAVES", "Stopping all services...");
	for (ioslaves::service* s : ioslaves::services_list) {
		if (s->ss_status_running == true)
			try {
				ioslaves::controlService(s, false, NULL);
			} catch (ioslaves::req_err& e) {}
	}
}

	/// Get service by name
ioslaves::service* ioslaves::getServiceByName (std::string name) {
	for (ioslaves::service* s : ioslaves::services_list) {
		if (s->s_name == name) 
			return s;
	}
	throw ioslaves::req_err(ioslaves::answer_code::NOT_FOUND, "SERVICE", logstream << "Service '" << name << "' not found !");
}

	/// Resumé of the serive's status
xif::polyvar ioslaves::serviceStatus (const ioslaves::service* s) {
	switch (s->s_type) {
		case ioslaves::service::type::SYSTEMCTL: return xif::polyvar();
		case ioslaves::service::type::PROG_DEAMON: return xif::polyvar();
		case ioslaves::service::type::IOSLPLUGIN: {
			if (not s->ss_status_running) return xif::polyvar();
			dl_t dl_handle = s->spec.plugin.handle;
			__extension__ ioslaves::api::status_info_f call_f = (ioslaves::api::status_info_f) ::dlsym(dl_handle, "ioslapi_status_info");
			if (call_f == NULL) 
				throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "API", logstream << "Error getting function with dlsym(\"ioslapi_status_info\") : " << ::dlerror());
			try {
				xif::polyvar* info = (*call_f)();
				RAII_AT_END_L( delete info );
				ioslaves::api::euid_switch(-1,-1);
				return *info;
			} catch (std::exception& e) {
				throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "API", logstream << "Error in ioslapi_status_info for '" << s->s_name << "' : " << e.what());
			}
		}
	}
	return xif::polyvar();
}

	/// Method for starting/stopping services
void ioslaves::controlService (ioslaves::service* s, bool start, const char* controlling_master) {
	logl_t l;
	switch (s->s_type) {
		case ioslaves::service::type::SYSTEMCTL: __log__(log_lvl::IMPORTANT, "SERVICE", logstream << (start?"Starting":"Stopping") << " service '" << s->s_name << "' as systemctl service '" << s->s_command << "'..."); break;
		case ioslaves::service::type::PROG_DEAMON:
			__log__(log_lvl::IMPORTANT, "SERVICE", logstream << (start?"Starting":"Stopping") << " daemon '" << s->s_name << "'...");
			break;
		case ioslaves::service::type::IOSLPLUGIN:
			if (start) __log__(log_lvl::IMPORTANT, "API", logstream << "Loading API service '" << s->s_name << "' (" << s->s_command << ".iosldl)...");
			else __log__(log_lvl::IMPORTANT, "OP", logstream << "Stopping API service '" << s->s_name << "'...");;
			break;
	}
	if (s->ss_status_running == start)
		throw ioslaves::req_err(ioslaves::answer_code::BAD_STATE, "SERVICE", logstream << "Can't " << (start?"start":"stop") << " service '" << s->s_name << "' : service is " << (start?"running":"stopped"));
	
	// Open/Close ports
	if (enable_upnp) {
		for (ioslaves::upnpPort p : s->s_ports) {
			try {
				if (start) ioslaves::upnpOpenPort(p);
				else		  ioslaves::upnpClosePort(p);
			} catch (ioslaves::upnpError& ue) {
				if (ue.fatal) 
					throw ioslaves::req_err(ioslaves::answer_code::UPNP_ERROR, "UPnP", logstream << "UPnP error : " << ue.what());
			}
		}
	}
	
	switch (s->s_type) {
		
		//-------------- Start/Stop Systemctl service
		case ioslaves::service::type::SYSTEMCTL: {
			std::string systemctl_string = _S( "systemctl ",(start?"start ":"stop "),s->s_command,".service" );
			int r;
			{ sigchild_block(); asroot_block();
				r = ::system(systemctl_string.c_str());
			}
			if (r == -1) throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "SERVICE", logstream << "system() failed to exec `systemctl` : " << ::strerror(errno));
			if (r != 0) throw ioslaves::req_err(ioslaves::answer_code::EXTERNAL_ERROR, "SERVICE", logstream << "`" << systemctl_string << "` command failed !");
			s->ss_status_running = start;
			s->ss_last_status_change = ::iosl_time();
			__log__(log_lvl::DONE, "SERVICE", logstream << "Successfully " << (start?"started":"stopped") << " service '" << s->s_name << "' with systemctl");
		} break;
		
		//-------------- Start/Stop API service
		case ioslaves::service::type::IOSLPLUGIN: {
			if (start) {
				std::string iosldl_path = _S( IOSLAVESD_API_DL_DIR,'/',s->s_command,".iosldl" );
				dl_t dl_handle = ::dlopen(iosldl_path.c_str(), RTLD_NOW|RTLD_LOCAL);
				if (dl_handle == NULL) {
					throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "API", logstream << "Couldn't load ioslaves dynamic API service with dlopen() : " << ::dlerror());
				}
				__extension__ ioslaves::api::set_callbacks_f set_service_callbacks = (ioslaves::api::set_callbacks_f) ::dlsym(dl_handle, "ioslapi_set_callbacks");
				if (set_service_callbacks == NULL) {
					::dlclose(dl_handle);
					throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "API", logstream << "Error getting function with dlsym(\"ioslapi_set_callbacks\") : " << ::dlerror());
				}
				(*set_service_callbacks)(s, signal_catch_sigchild_p, hostname, ioslaves::api::common_vars, IOSLAVED_API_MAIN_PROG_CALLBACKS_TO_SET);
				__extension__ ioslaves::api::start_f start_service_func = (ioslaves::api::start_f) ::dlsym(dl_handle, "ioslapi_start");
				if (start_service_func == NULL) {
					::dlclose(dl_handle);
					throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "API", logstream << "Error getting function with dlsym(\"ioslapi_start\") : " << ::dlerror());
				}
				try {
					bool ok = (*start_service_func)(controlling_master);
					ioslaves::api::euid_switch(-1,-1);
					if (not ok) 
						throw std::runtime_error("failed");
				} catch (std::exception& e) {
					::dlclose(dl_handle);
					throw ioslaves::req_err(ioslaves::answer_code::EXTERNAL_ERROR, "API", logstream << "Error in start method of service '" << s->s_name << "' : " << e.what());
				}
				s->spec.plugin.handle = dl_handle;
			} else {
				dl_t dl_handle = s->spec.plugin.handle;
				__extension__ ioslaves::api::stop_f stop_func = (ioslaves::api::stop_f) ::dlsym(dl_handle, "ioslapi_stop");
				if (stop_func == NULL) 
					throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "API", logstream << "Error getting function with dlsym(\"ioslapi_stop\") : " << ::dlerror());
				try {
					(*stop_func)();
					ioslaves::api::euid_switch(-1,-1);
				} catch (std::exception& e) {
					__log__(log_lvl::ERROR, "API", logstream << "Error in stop method of service '" << s->s_name << "' : " << e.what());
				}
				::dlclose(dl_handle);
				s->spec.plugin.handle = NULL;
			}
			s->ss_status_running = start;
			s->ss_last_status_change = ::iosl_time();
			__log__(log_lvl::DONE, "API", logstream << "Successfully " << (start?"loaded":"unloaded") << " API service '" << s->s_name << "'");
		} break;
		
		//-------------- Start/Stop daemon executable
		case ioslaves::service::type::PROG_DEAMON: {
			std::function<pid_t()> file_get_pid = [&]()-> pid_t {
				ssize_t rs;
				fd_t pid_f = ::open(s->spec.exec.pid_file, O_RDONLY);
				if (pid_f == INVALID_HANDLE) {
					if (errno == ENOENT) 
						return -ENOENT;
					else 
						throw xif::sys_error("can't open PID file");
				}
				char buf[5];
				rs = ::read(pid_f, buf, 5);
				for (size_t i = 0; i < (size_t)rs; i++) 
					if (not ::isdigit(buf[i])) { buf[i] = '\0'; rs = i; break; }
				::close(pid_f);
				if (rs < 1) {
					return -ENOSTR;
				} else {
					try {
						pid_t pid = ::atoix<pid_t>(std::string(buf, (size_t)rs));
						if (pid == 0) return -EINVAL;
						return pid;
					} catch (std::runtime_error) {
						return -EINVAL;
					}
				}
			};
			try {
				int r;
				if (start) {
					pid_t pid = file_get_pid();
					if (pid > 0) {
				#ifdef __APPLE__
						char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
						r = ::proc_pidpath(pid, pathbuf, sizeof(pathbuf));
						if (r == 0) {
							if (errno == ESRCH)
								 goto __start_proc;
							throw xif::sys_error("failed to get proc name");
						}
						std::string proc_path = pathbuf;
						__log__(log_lvl::LOG, "DEAMON", logstream << "Process cmdline of pid " << pid << " : `" << proc_path << "`");
						if (::strlen(s->spec.exec.execnam) == 0 or proc_path.find(s->spec.exec.execnam)) 
							goto __proc_validated;
				#elif __linux__
						ssize_t rs;
						char pathbuf[128];
						std::string proc_name;
						fd_t proc_cmd_f = ::open( _s("/proc/",::ixtoa(pid),"/comm"), O_RDONLY);
						if (proc_cmd_f == -1) 
							goto __start_proc;
						RAII_AT_END_L( ::close(proc_cmd_f) );
						if (::strlen(s->spec.exec.execnam) == 0) 
							goto __proc_validated;
						rs = ::read(proc_cmd_f, pathbuf, sizeof(pathbuf));
						if (rs > 0) {
							proc_name = std::string(pathbuf, rs);
							__log__(log_lvl::LOG, "DEAMON", logstream << "Process name of pid " << pid << " : `" << proc_name << "`");
							if (proc_name == s->spec.exec.execnam) 
								goto __proc_validated;	
						}
				#else
						#warning PID checking : Platform not supported
						goto __proc_validated;
				#endif
						throw ioslaves::req_err(ioslaves::answer_code::BAD_STATE, "DAEMON", logstream << "A process with PID " << pid << " already exists but its name doesn't match");
					__proc_validated:
						__log__(log_lvl::WARNING, "DAEMON", logstream << "Daemon of service '" << s->s_name << "' seems to be already started with pid " << pid);
						goto __daemon_end;
					}
				__start_proc:
					{ sigchild_block(); asroot_block();
						r = ::system(s->s_command.c_str());
					}
					if (r == -1) throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "DAEMON", logstream << "system() failed to exec daemon command : " << ::strerror(errno));
					if (r != 0) throw ioslaves::req_err(ioslaves::answer_code::EXTERNAL_ERROR, "DAEMON", logstream << "`" << s->s_command << "` command failed !");
				} else {
					const char* daemon_dead_why = "?";
					pid_t pid = file_get_pid();
					if (pid < 0) {
						if (pid == -EINVAL) daemon_dead_why = "PID value in file is invalid";
						else if (pid == -ENOSTR) daemon_dead_why = "Nothing in PID file";
						else if (pid == -ENOENT) daemon_dead_why = "PID file not found";
						goto __daemon_dead;
					}
					__log__(log_lvl::LOG, "DAEMON", logstream << "Killing process PID " << pid << "...", LOG_WAIT, &l);
					{ asroot_block();
						r = ::kill(pid, SIGTERM);
					}
					if (r == -1) {
						if (errno == ESRCH) daemon_dead_why = "Process not found";
						else throw xif::sys_error("Can't kill process");
						goto __daemon_dead;
					} else 
						__log__(log_lvl::DONE, "DAEMON", "Done !", LOG_ADD, &l);
					goto __daemon_end;
				__daemon_dead:
					s->ss_status_running = false;
					s->ss_last_status_change = ::iosl_time();
					throw ioslaves::req_err(ioslaves::answer_code::BAD_STATE, "DAEMON", logstream << "Process of service `" << s->s_name << "` is probably already dead : " << daemon_dead_why);
				}
			__daemon_end:
				s->ss_status_running = start;
				s->ss_last_status_change = ::iosl_time();
				__log__(log_lvl::DONE, "DAEMON", logstream << "Successfully " << (start?"started":"stopped") << " service '" << s->s_name << "' as daemon");
			} catch (xif::sys_error& syserr) {
				throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "DAEMON", syserr.what());
				return;
			}
		} break;
	}
	
}
