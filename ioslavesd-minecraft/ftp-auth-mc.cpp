/**********************************************************\
 *               -== Xif Network project ==-
 *                   ioslavesd minecraft
 *   pure-ftpd external auth method for minecraft service
 * *********************************************************
 * Copyright © Félix Faisant 2013-2014. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common
#define IOSLAVESD_API_SERVICE
#include "api.h"
using namespace xlog;
#define IOSLAVESD_MINECRAFT
#include "minecraft.h"

	// Misc
#include <xifutils/cxx.hpp>
#include <xifutils/intstr.hpp>
#include <list>

	// UNIX Socket & pure-ftpd
#include <socket++/base_unixsock.hpp>
#include <socket++/handler/socket_server.hpp>
#include <socket++/io/text_buffered.hpp>
#define PURE_AUTHD_AUTH_SOCK_PATH "/var/run/pure-authd-mc.sock"
pid_t minecraft::pure_ftpd_pid = -1;
std::string minecraft::ftp_serv_addr;
in_port_t minecraft::pure_ftpd_base_port = 210;
in_port_t minecraft::pure_ftpd_pasv_range_beg = 30000;
uint8_t minecraft::pure_ftpd_max_cli = 10;
#define PURE_FTPD_BASE_PORT pure_ftpd_base_port
#define PURE_FTPD_MAX_CLI pure_ftpd_max_cli
#define PURE_FTPD_PASV_RANGE_SZ (2*PURE_FTPD_MAX_CLI)
#define PURE_FTPD_PASV_RANGE_BEG pure_ftpd_pasv_range_beg
#define PURE_FTPD_PORT_MAX_TRY 20

	// Thread
#include <pthread.h>
namespace minecraft {
	
	void* mc_ftpd_auth_thread (void* arg);
	void ftp_start_thread ();
	fd_t ftp_stopfd;
	bool ftp_th_started = false;
	pthread_t ftp_thread;
	
}

	// Pure-FTPd
namespace minecraft {
const char* const pure_in_fields[] = { "account", "password", "localhost", "localport", "peer", "encrypted", NULL };
struct pure_in_reqst { std::string      username,     passwd,    local_ip,  local_port,     ip,   encrypted; };
}

	// Auth sessions
namespace minecraft {
	struct ftp_auth {
		std::string username;
		std::string md5passwd;
		std::string path;
		std::string server;
		time_t end_validity;
	};
	std::list<ftp_auth> ftp_sessions;
}

	// Start thread
void minecraft::ftp_start_thread () {
	__log__(log_lvl::NOTICE, "FTP", "Creating FTP authentfication thread...");
	
	int r;
	fd_t stop_pipe[2];
	r = ::pipe(stop_pipe);
	if (r == -1) 
		throw xif::sys_error("create stop pipe for ftp thread");
	minecraft::ftp_stopfd = stop_pipe[1];
	
	r = ::pthread_create(&minecraft::ftp_thread, NULL, &mc_ftpd_auth_thread, new fd_t(stop_pipe[0]));
	if (r != 0)
		throw xif::sys_error("can't create ftp auth thread");
	
	uint8_t i = 0;
	do { 
		::usleep(100000);
		if (i == 20) {
			minecraft::ftp_th_started = false;
			throw ioslaves::req_err(ioslaves::answer_code::ERROR, "FTP", "Auth thread not responding after 2 seconds");
		}
		i++;
	} while (minecraft::ftp_serv_addr.empty());
}
void minecraft::ftp_stop_thead (int why) {
	int r;
	if (not minecraft::ftp_th_started) 
		return;
	if (why == INT32_MAX) {
		asroot_block();
		__log__(log_lvl::LOG, "FTP", "Stopping FTP auth thread...");
		r = ::kill(pure_ftpd_pid, SIGHUP);
		if (r == -1) 
			__log__(log_lvl::WARNING, "FTP", logstream << "Failed to kill pure-ftpd : " << ::strerror(errno));
	} else {
		if (not minecraft::ftp_th_started) return;
		__log__(log_lvl::WARNING, "FTP", logstream << "pure-ftpd stopped with code " << why << ". Stopping FTP auth thread...");
		::sleep(2);
	}
	errno = 0;
	r = (int)::write(minecraft::ftp_stopfd, "", 1);
	if (r != 1) 
		__log__(log_lvl::WARNING, "FTP", logstream << "Failed to send stop signal to thread : " << ::strerror(errno));
	do { 
		::usleep(100000);
	} while (minecraft::ftp_th_started);
}

	// Listening thread
void* minecraft::mc_ftpd_auth_thread (void* arg) {
	
	logl_t l;
	fd_t stopfd = *(fd_t*)arg; delete (fd_t*)arg;
	in_port_t ftp_port = 0;
	in_port_t ftp_ports_pasv_beg = 0;
	
	minecraft::ftp_th_started = true;
	RAII_AT_END({
		minecraft::pure_ftpd_pid = -1;
		minecraft::ftp_th_started = false;
		::close(stopfd);
		::close(minecraft::ftp_stopfd);
		minecraft::ftp_serv_addr.clear();
		minecraft::ftp_sessions.clear();
		__log__(log_lvl::LOG, "FTP", "Thread end");
	});
	
	try {
		
		auto _sock_p = new socketxx::end::socket_server<socketxx::base_unixsock,void> (socketxx::base_unixsock::addr_info(PURE_AUTHD_AUTH_SOCK_PATH));
		{ asroot_block();
			_sock_p->listening_start(2, false);
		}
		RAII_AT_END_N(sock, {
			asroot_block();
			_sock_p->listening_stop();
			delete _sock_p;
		});
		socketxx::end::socket_server<socketxx::base_unixsock,void>& authsock = *_sock_p;
		authsock.fcntl_flags() += FD_CLOEXEC;
		
		__log__(log_lvl::DONE, "FTP", logstream << "Thread pure-authd now listens on local socket");
		
			// Autoclose ports
		RAII_AT_END_N(ports, {
			if (ftp_port != 0) 
				(*ioslaves::api::close_port)(ftp_port, 1, true);
			if (ftp_ports_pasv_beg != 0) 
				(*ioslaves::api::close_port)(ftp_ports_pasv_beg, PURE_FTPD_PASV_RANGE_SZ, true);
		});
		
			// FTP listening port
		ftp_port = PURE_FTPD_BASE_PORT;
		goto __scan;
	__new_port:
		if (++ftp_port == PURE_FTPD_BASE_PORT + PURE_FTPD_PORT_MAX_TRY) {
			__log__(log_lvl::SEVERE, "FTP", logstream << "Port range entierly used !");
			return NULL;
		}
	__scan:
		errno = 0;
		ioslaves::answer_code open_port_answ = (*ioslaves::api::open_port)(ftp_port, true, ftp_port, 1, "minecraft ftp server");
		if (open_port_answ != ioslaves::answer_code::OK) {
			if (open_port_answ == ioslaves::answer_code::EXISTS or errno == 718 /*ConflictInMappingEntry*/)
				goto __new_port;
			__log__(log_lvl::ERROR, "FTP", logstream << "Failed to open port " << ftp_port << " : " << ioslaves::getAnswerCodeDescription(open_port_answ));
			return NULL;
		}
		
			// FTP passive mode ports
		ftp_ports_pasv_beg = PURE_FTPD_PASV_RANGE_BEG;
		goto __test_range;
	__new_range:
		ftp_ports_pasv_beg += PURE_FTPD_PASV_RANGE_SZ;
		if (ftp_ports_pasv_beg > PURE_FTPD_PASV_RANGE_BEG + PURE_FTPD_PORT_MAX_TRY*PURE_FTPD_PASV_RANGE_SZ) {
			__log__(log_lvl::SEVERE, "FTP", logstream << "Port range for passive mode entierly used !");
			return NULL;
		}
	__test_range:
		errno = 0;
		open_port_answ = (*ioslaves::api::open_port)(ftp_ports_pasv_beg, true, ftp_ports_pasv_beg, PURE_FTPD_PASV_RANGE_SZ, "minecraft ftp server pasv");
		if (open_port_answ != ioslaves::answer_code::OK) {
			if (open_port_answ == ioslaves::answer_code::EXISTS or errno == 718 /*ConflictInMappingEntry*/)
				goto __new_range;
			__log__(log_lvl::ERROR, "FTP", logstream << "Failed to open port range " << ftp_ports_pasv_beg << "-" << ftp_ports_pasv_beg+PURE_FTPD_PASV_RANGE_SZ);
			return NULL;
		}
		
		minecraft::ftp_serv_addr = _S(ioslaves::api::slave_name,'.',XIFNET_SLAVES_DOM,":",::ixtoa(ftp_port));
		
		__log__(log_lvl::LOG, "FTP", logstream << "Starting pure-ftpd on port " << ftp_port << "...", LOG_WAIT, &l);
		{ asroot_block();
		pure_ftpd_pid = 
		ioslaves::fork_exec("pure-ftpd", 
		                    {
									  _S("--login=extauth:",PURE_AUTHD_AUTH_SOCK_PATH), 
									  "--bind", ::ixtoa(ftp_port), 
									  "--chrooteveryone", 
									  _S("--maxclientsnumber=",::ixtoa(PURE_FTPD_MAX_CLI)), 
									  "--noanonymous", 
									  _S("--forcepassiveip=",ioslaves::api::slave_name,'.',XIFNET_SLAVES_DOM), 
									  _S("--passiveportrange=",::ixtoa(ftp_ports_pasv_beg),':',::ixtoa(ftp_ports_pasv_beg+PURE_FTPD_PASV_RANGE_SZ-1)),
									  "--nochmod",
									  _S("--minuid=",::ixtoa(java_user_id))
								  }, 
								  false, NULL, true, 0, 0, true).first;
		}
		__log__(log_lvl::DONE, "FTP", "Done", LOG_ADD, &l);

		authsock.wait_activity_loop(NULL, 
				// New client
			[&](socketxx::end::socket_server<socketxx::base_unixsock,void>::client cli) -> socketxx::pool_ret_t {
				__log__(log_lvl::LOG, "FTP", logstream << "New authentication request");
				pure_in_reqst fields;
				
				socketxx::io::text_socket<socketxx::base_unixsock> s (cli);
				s.set_line_sep("\n");
				for (size_t i = 0; pure_in_fields[i] != NULL; i++) {
					std::string field = s.i_line();
					if (field.find(pure_in_fields[i]) != 0) {
						__log__(log_lvl::ERROR, "FTP", logstream << "Ill auth request");
						return socketxx::POOL_QUIT;
					}
					field.erase(field.begin(), field.begin()+::strlen(pure_in_fields[i])+1);
					*(((std::string*)(&fields))+(off_t)i) = field;
				}
				s.i_line();
				
				__log__(log_lvl::NOTICE, "FTP", logstream << "Verifying user '" << fields.username << "' IP " << fields.ip << "...");
				for (auto it = ftp_sessions.begin(); it != ftp_sessions.end();) {
					if (it->end_validity < ::time(NULL)) {
						__log__(log_lvl::LOG, "FTP", logstream << "FTP session for user '" << it->username << "' invalidated");
						auto p_it = it++; ftp_sessions.erase(p_it);
					} else {
						if (fields.username == it->username) {
							
							if (fields.passwd == "x") {
								__log__(log_lvl::NOTICE, "FTP", logstream << "Special password : deleting session of '" << fields.username << "'");
								ftp_sessions.erase(it);
								return socketxx::POOL_CONTINUE;
							}
							
							if (it->md5passwd != ioslaves::md5(fields.passwd)) {
								__log__(log_lvl::NOTICE, "FTP", logstream << "Wrong password for user '" << fields.username << "'");
								ftp_sessions.erase(it);
								s.o_line("auth_ok:-1");
								s.o_line("end");
								return socketxx::POOL_CONTINUE;
							}
							
							__log__(log_lvl::DONE, "FTP", logstream << "User '" << fields.username << "' is succesfully authenticated for FTP session at " << it->path);
							it->end_validity += 60;
							s.o_line("auth_ok:1");
							s.o_line(_S("uid:",::ixtoa(java_user_id)));
							s.o_line(_S("gid:",::ixtoa(java_group_id)));
							s.o_line(_S("dir:",it->path));
							s.o_line("per_user_max:1");
							s.o_line("end");
							return socketxx::POOL_CONTINUE;
							
						}
						++it;
					}
				}
				
				__log__(log_lvl::NOTICE, "FTP", logstream << "User '" << fields.username << "' not found or expired");
				s.o_line("auth_ok:0");
				s.o_line("end");
				return socketxx::POOL_CONTINUE;
			},
				// Stop FD
			stopfd, [](fd_t) -> socketxx::pool_ret_t { return socketxx::POOL_QUIT; }
		);
		
	} catch (socketxx::end::server_launch_error& e) {
		__log__(log_lvl::ERROR, "FTP", logstream << "Can't create listening local socket : " << e.what());
	} catch (socketxx::error& e) {
		__log__(log_lvl::ERROR, "FTP", logstream << "Network error : " << e.what());
	}
	return NULL;
}

	// Prepare user FTP session, from panel
void minecraft::ftp_register_user (std::string username, std::string md5passwd, std::string server, std::string map, time_t validity) {
	if (not minecraft::ftp_th_started) 
		minecraft::ftp_start_thread();
	for (auto it = minecraft::ftp_sessions.begin(); it != minecraft::ftp_sessions.end();) {
		if (it->end_validity < ::time(NULL)) {
			__log__(log_lvl::LOG, "FTP", logstream << "FTP session for user '" << it->username << "' invalidated");
			auto p_it = it++; minecraft::ftp_sessions.erase(p_it);
		} else {
			if (username == it->username) 
				throw ioslaves::req_err(ioslaves::answer_code::EXISTS, "FTP", logstream << "A valid session for username '" << username << "' for server '" << it->server << "' already exists");
			++it;
		}
	}
	minecraft::ftp_auth sess;
	sess.username = username;
	for (size_t i = 0; i < md5passwd.length(); i++) 
		md5passwd[i] = ::tolower(md5passwd[i]);
	sess.md5passwd = md5passwd;
	sess.end_validity = ::time(NULL) + validity;
	sess.path = _S( MINECRAFT_SRV_DIR,"/mc_",server,'/',map );
	sess.server = server;
	minecraft::ftp_sessions.insert(ftp_sessions.begin(), sess);
	__log__(log_lvl::DONE, "FTP", logstream << "FTP session created for user " << sess.username << " valid for " << validity << " seconds");
}

	// Delete all FTP sessions for a server
void minecraft::ftp_del_sess_for_serv (std::string server, time_t terminal_valididy) {
	for (auto it = minecraft::ftp_sessions.begin(); it != minecraft::ftp_sessions.end();) {
		if (it->end_validity < ::time(NULL)) {
			__log__(log_lvl::LOG, "FTP", logstream << "FTP session for user '" << it->username << "' invalidated");
			auto p_it = it++; minecraft::ftp_sessions.erase(p_it);
		} else if (it->server == server) {
			if (terminal_valididy == 0) {
				__log__(log_lvl::LOG, "FTP", logstream << "Deleting FTP session for user '" << it->username << "'");
				auto p_it = it++; minecraft::ftp_sessions.erase(p_it);
			} else {
				__log__(log_lvl::LOG, "FTP", logstream << "Set terminal validity of FTP session for user '" << it->username << "' to " << terminal_valididy << "s");
				it->end_validity = ::time(NULL) + terminal_valididy;
				it++;
			}
		} else 
			++it;
	}
}