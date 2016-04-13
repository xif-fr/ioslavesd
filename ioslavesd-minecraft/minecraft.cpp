/**********************************************************\
 *             ioslaves : ioslavesd-minecraft
 *  Minecraft servers dynamic hosting service for ioslavesd
 * *********************************************************
 * Copyright © Félix Faisant 2013-2016. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// ioslavesd API
#define IOSLAVESD_API_SERVICE
#define IOSLAVESD_API_SERVICE_IMPL
#include "api.h"
using namespace xlog;

	// Common Minecraft
#define IOSLAVESD_MINECRAFT
#include "minecraft.h"

	// General and misc
#include <xifutils/cxx.hpp>
#include <xifutils/intstr.hpp>
#include <xifutils/polyvar.hpp>
#include <vector>
#include <list>
#include <map>
#include <iomanip>
#include <time.h>
#include <sys/time.h>

	// User
#include <pwd.h>
	// Run a block of code as mcjava (errno is preserved, ioslaves uid/gid restored)
struct _block_as_mcjava {
	_block_as_mcjava () { ioslaves::api::euid_switch(minecraft::java_user_id, minecraft::java_user_id); }
	~_block_as_mcjava () { ioslaves::api::euid_switch(-1,-1); }
};
#define block_as_mcjava() _block_as_mcjava _block_as_mcjava_handle

	// Network
#include <socket++/io/simple_socket.hpp>
#include <socket++/handler/socket_client.hpp>
#include <socket++/base_inet.hpp>
#include <socket++/quickdefs.h>

	// Files
#include <sys/stat.h>
#include <sys/dir.h>
#include <fstream>

	// Conf files
#define private public
#include <libconfig.h++>
#undef private
#define MINECRAFT_CONF_FILE MINECRAFT_SRV_DIR"/ioslmc.conf"
#define MINECRAFT_REPORTS_FILE MINECRAFT_SRV_DIR"/ioslmc-reports.conf"

	// Signals and threads
#include <signal.h>
#include <sys/wait.h>
#define MUTEX_PRELOCK pthread_mutex_log(NULL,"will lock",&minecraft::servs_mutex);
#define MUTEX_POSTLOCK pthread_mutex_log(NULL,"locked",&minecraft::servs_mutex);
#define MUTEX_UNLOCKED pthread_mutex_log(NULL,"unlocked",&minecraft::servs_mutex);

	// Minecraft service
namespace minecraft {
	
	struct serv {
		pthread_t s_thread;
		std::string s_wdir;
		fd_t s_early_pipe = INVALID_HANDLE;
		fd_t s_sock_comm = INVALID_HANDLE;
		std::string s_servid;
		ioslaves::version s_mc_ver = ioslaves::version(0,0,0);
		std::string s_jar_path;
		std::string s_map;
		bool s_is_perm_map;
		minecraft::serv_type s_serv_type;
		in_port_t s_port = 0;
		std::vector<in_port_t> s_oth_ports;
		pid_t s_java_pid = -1;
		unsigned short s_megs_ram = 0;
		uint8_t s_viewdist;
		time_t s_start_iosl_time = 0;
		time_t s_delay_noplayers = 0;
	};
	
	#define MCLOGSCLI(s) logstream << '[' << s->s_servid << "] "
	#define MCLOGCLI(servid) logstream << '[' << servid << "] "
	#define THLOGSCLI(s) _s("Thread:",s->s_servid)
	
	enum class internal_serv_op_code : char {
		CHAT_WITH_CLIENT,
		STOP_SERVER_NOW,
		STOP_SERVER_CLI,
		GOT_SIGNAL,
		KILL_JAVA,
		GET_PLAYER_LIST
	};
	
	struct serv_stopped { 
		std::string serv;
		std::string map_to_save;
		minecraft::whyStopped why;
		bool gracefully;
		bool doneDone;
	};
	std::list<serv_stopped> servs_stopped;
	std::list<minecraft::serv*> opening_servs;
	std::map<std::string,minecraft::serv*> servs;
	pthread_mutex_t servs_mutex = PTHREAD_MUTEX_INITIALIZER;
		/* Note : the mutex MUST be acquired on access of these lists, including when getting minecraft::serv*, and retained as long as the serv* is used */
	
		// Vars
	uid_t java_user_id = 0;
	gid_t java_group_id = 0;
	in_port_t servs_port_range_beg = 25566, servs_port_range_sz = 33;
	uint8_t max_viewdist = 6;
	bool ignore_shutdown_time = false;
	bool refuse_mode = false;
	
		// Start and Stop Minecraft server
	void startServer (socketxx::io::simple_socket<socketxx::base_socket> cli, std::string servid);
	void* serv_thread (void* arg);
	void stopServer (socketxx::io::simple_socket<socketxx::base_socket> cli, minecraft::serv* s, pthread_mutex_handle&);
	
		// Transfer, files, and world functions
	void transferAndExtract (socketxx::io::simple_socket<socketxx::base_socket> sock, minecraft::transferWhat what, std::string name, std::string parent_dir, bool alt = false);
	bool compressAndSend (socketxx::io::simple_socket<socketxx::base_socket> sock, std::string servname, std::string mapname, bool async);
	void unzip (const char* file, const char* in_dir, const char* expected_dir_name);
	void deleteMapFolder (minecraft::serv* s);
	void cpTplDir (const char* tpl_dir, std::string working_dir);
	time_t lastsaveTimeFile (std::string path, bool set);
	void deleteLckFiles (std::string in_dir);
	
		// Files and templates
	void processTemplateFile (const char* file, std::map<std::string,std::string> hashlist, std::string header);
	struct _BigFiles_entry { std::string name; std::string final_path; };
	std::vector<_BigFiles_entry> getBigFilesIndex (std::string serv_path);
	
}

/** -----------------------	**/
/**      API methods   	   	**/
/** -----------------------	**/

	// Start Minecraft service
extern "C" bool ioslapi_start (const char* by_master) {
	logl_t l;
	__log__(log_lvl::IMPORTANT, NULL, logstream << "Starting Minecraft Servers Distributed Hosting...");
	
		// Minecraft user for executing java
	int r;
	errno = 0;
	long _pwbufsz = ::sysconf(_SC_GETPW_R_SIZE_MAX);
	if (_pwbufsz < 1) _pwbufsz = 100;
	char pwbuf[_pwbufsz];
	struct passwd userinfo, *_p_userinfo;
	r = ::getpwnam_r(MINECRAFT_JAVA_USER, &userinfo, pwbuf, _pwbufsz, &_p_userinfo);
	if (r == -1 or _p_userinfo == NULL) {
		__log__(log_lvl::FATAL, NULL, logstream << "Failed to get user id for executing java : " << (_p_userinfo==NULL ? "user not found" : ::strerror(errno)));
		return false;
	}
	minecraft::java_user_id = userinfo.pw_uid;
	minecraft::java_group_id = userinfo.pw_gid;
	
		// Load conf file
	__log__(log_lvl::LOG, NULL, logstream << "Loading conf file...");
	libconfig::Config conf;
	try {
		conf.readFile(MINECRAFT_CONF_FILE);
		{
			minecraft::servs_port_range_beg = (int)conf.lookup("servs_port_range_beg");
			minecraft::servs_port_range_sz = (int)conf.lookup("servs_port_range_sz");
			minecraft::max_viewdist = (int)conf.lookup("max_viewdist");
			minecraft::pure_ftpd_base_port = (int)conf.lookup("ftp_base_port");
			minecraft::pure_ftpd_pasv_range_beg = (int)conf.lookup("ftp_pasv_range_beg");
			minecraft::pure_ftpd_max_cli = (int)conf.lookup("ftp_max_cli");
			minecraft::ignore_shutdown_time = (bool)conf.lookup("ignore_shutdown_time");
		}
	} catch (const libconfig::ConfigException& ce) {
		__log__(log_lvl::FATAL, "CONF", logstream << "Reading configuration file " << MINECRAFT_CONF_FILE << " failed : " << ce.what());
		return false;
	}
	
		// Load stop reports
	libconfig::Config savereports;
	try {
		savereports.readFile(MINECRAFT_REPORTS_FILE);
		__log__(log_lvl::LOG, NULL, "Loading stop reports...", LOG_WAIT, &l);
		libconfig::Setting& replist = savereports.getRoot();
		try {
			for (int i = 0; i < replist.getLength(); i++) {
				libconfig::Setting& rep = replist[i];
				rep.assertType(libconfig::Setting::TypeGroup);
				minecraft::serv_stopped ss;
				ss.serv = std::string(rep.getName());
				ss.map_to_save = rep["maptosave"].operator std::string();
				ss.why = (minecraft::whyStopped)(int)rep["why"];
				ss.gracefully = (bool)rep["gracefully"];
				minecraft::servs_stopped.push_back(ss);
				__log__(log_lvl::LOG, NULL, ss.serv, LOG_ADD|LOG_WAIT, &l);
			}
			__log__(log_lvl::DONE, NULL, "Done", LOG_ADD, &l);
		} catch (const libconfig::SettingException& e) {
			__log__(log_lvl::ERROR, NULL, logstream << "Error while loading stop report : " << e.what());
		}
	} catch (const libconfig::ParseException& e) {
		__log__(log_lvl::ERROR, NULL, logstream << "Parse error in stop reports save file at line " << e.getLine());
	} catch (const libconfig::FileIOException&) {
	}
	r = ::unlink(MINECRAFT_REPORTS_FILE);
	
	return true;
}

	// Stop Minecraft service
extern "C" void ioslapi_stop (void) {
	logl_t l;
	__log__(log_lvl::IMPORTANT, NULL, logstream << "Stopping Minecraft Service... Stopping all servers...");
	
		// Send close request to servers
	try {
		pthread_mutex_handle_lock(minecraft::servs_mutex);
		for (std::pair<std::string,minecraft::serv*> p : minecraft::servs) {
			socketxx::io::simple_socket<socketxx::base_fd> s_comm (socketxx::base_fd(p.second->s_sock_comm, SOCKETXX_MANUAL_FD));
			s_comm.o_char((char)minecraft::internal_serv_op_code::STOP_SERVER_NOW);
		}
	} catch (const socketxx::error& e) {
		__log__(log_lvl::FATAL, "COMM", logstream << "Failed to send stop request to server thread : " << e.what());
	}
	
		// Wait for servers
	MUTEX_PRELOCK; ::pthread_mutex_lock(&minecraft::servs_mutex); MUTEX_POSTLOCK;
	if (not minecraft::servs.empty()) {
		__log__(log_lvl::LOG, NULL, logstream << "Waiting for threads exiting...", LOG_WAIT, &l);
		while (not minecraft::servs.empty()) {
			::pthread_mutex_unlock(&minecraft::servs_mutex); MUTEX_UNLOCKED;
			::usleep(500000);
			MUTEX_PRELOCK; ::pthread_mutex_lock(&minecraft::servs_mutex); MUTEX_POSTLOCK;
		}
		__log__(log_lvl::DONE, NULL, logstream << "Done !", LOG_ADD, &l);
	}
	::pthread_mutex_unlock(&minecraft::servs_mutex); MUTEX_UNLOCKED; // We are now free
	
		// Stop FTP server
	minecraft::ftp_stop_thead(INT32_MAX);
	
		// Stop reports
	if (minecraft::servs_stopped.size() != 0) {
		__log__(log_lvl::NOTICE, NULL, logstream << "Saving " << minecraft::servs_stopped.size() << " stop reports...", LOG_WAIT, &l);
		libconfig::Config savereports;
		libconfig::Setting& replist = savereports.getRoot();
		for (minecraft::serv_stopped& ss : minecraft::servs_stopped) {
			__log__(log_lvl::LOG, NULL, ss.serv, LOG_ADD|LOG_WAIT, &l);
			libconfig::Setting& report = replist.add(ss.serv, libconfig::Setting::TypeGroup);
			report.add("gracefully", libconfig::Setting::TypeBoolean) = ss.gracefully;
			report.add("maptosave", libconfig::Setting::TypeString) = ss.map_to_save;
			report.add("why", libconfig::Setting::TypeInt) = (int)ss.why;
		}
		try {
			savereports.writeFile(MINECRAFT_REPORTS_FILE);
			__log__(log_lvl::DONE, NULL, "Done", LOG_ADD, &l);
		} catch (const libconfig::FileIOException& e) {
			__log__(log_lvl::ERROR, NULL, logstream << "Failed to save reports : " << e.what());
		}
	}
	
}

	// Inhibit auto shutdown if something is started
extern "C" bool ioslapi_shutdown_inhibit () {
	return minecraft::servs.size() != 0;
}

	// Returns a small resumé of the Minecraft service
extern "C" xif::polyvar* ioslapi_status_info () {
	std::map<std::string, socketxx::io::simple_socket<socketxx::base_fd>> pending_requests;
	std::map<std::string, bool> servs_fixed;
	MUTEX_PRELOCK; ::pthread_mutex_lock(&minecraft::servs_mutex); MUTEX_POSTLOCK;
	for (std::pair<std::string,minecraft::serv*> p : minecraft::servs) {
		try {
			socketxx::io::simple_socket<socketxx::base_fd> s_comm(socketxx::base_fd(p.second->s_sock_comm, SOCKETXX_MANUAL_FD));
			s_comm.o_char((char)minecraft::internal_serv_op_code::GET_PLAYER_LIST);
			pending_requests.insert({p.first, s_comm});
			servs_fixed[p.first] = not 
				ioslaves::infofile_get(_s( MINECRAFT_SRV_DIR,"/mc_",p.first,'/',p.second->s_map,"/fixed_map" ), true).empty();
		} catch (...) {}
	}
	::pthread_mutex_unlock(&minecraft::servs_mutex); MUTEX_UNLOCKED;
	xif::polyvar servers = std::vector<xif::polyvar>();
	for (auto p : pending_requests) {
		servers.v().push_back(p.first);
		try {
			if ((ioslaves::answer_code)p.second.i_char() == ioslaves::answer_code::OK) {
				servers.v().back().s() += _S( " (",::ixtoa(p.second.i_int<int16_t>()),")" );
				p.second.i_int<uint32_t>();
			}
		} catch (...) {}
		if (servs_fixed[p.first] == true) 
			servers.v().back().s() += " fix";
	}
	xif::polyvar* info = new xif::polyvar(xif::polyvar::map({
		{"#", servers.v().size()}, 
		{"servers", servers}}
	));
	if (minecraft::refuse_mode == true)
		info->m()["refuse-servs"] = "y";
	return info;
}

	// Check if we are the owner of this terminated process pid, and then inform server thread.
extern "C" bool ioslapi_got_sigchld (pid_t pid, int pid_status) {
	if (minecraft::pure_ftpd_pid != -1 and minecraft::pure_ftpd_pid == pid) {
		minecraft::ftp_stop_thead(pid_status);
		return true;
	}
	pthread_mutex_handle_lock(minecraft::servs_mutex);
	std::function<bool(minecraft::serv*)> test_serv = [&] (minecraft::serv* s) -> bool {
		if (s->s_java_pid == pid) {
			try {
				socketxx::io::simple_socket<socketxx::base_fd> s_comm (socketxx::base_fd(s->s_sock_comm, SOCKETXX_MANUAL_FD));
				s_comm.o_char((char)minecraft::internal_serv_op_code::GOT_SIGNAL);
				s_comm.o_int<int>(pid_status);
			} catch (const socketxx::error& e) {
				__log__(log_lvl::ERROR, NULL, logstream << "Error while sending sigchild to thread of server " << s->s_servid << " : " << e.what());
			}
			return true;
		} return false;
	};
	for (std::pair<std::string,minecraft::serv*> p : minecraft::servs) 
		if (test_serv(p.second) == true) return true;
	for (minecraft::serv* s : minecraft::opening_servs) 
		if (test_serv(s) == true) return true;
	return false;
}

extern "C" void ioslapi_net_client_call (socketxx::base_socket& _cli_sock, const char* masterid, ioslaves::api::api_perm_t* perms, in_addr_t) {
	int r;
	logl_t l;
	
	if (perms == NULL) 
		throw ioslaves::req_err(ioslaves::answer_code::NOT_AUTHORIZED, "PERMS", logstream << "Minecraft API service requires authentication", log_lvl::OOPS);
	
	try {
		socketxx::io::simple_socket<socketxx::base_socket> cli (_cli_sock);
		timeval utc_time; ::gettimeofday(&utc_time, NULL);
		cli.o_int<int64_t>(utc_time.tv_sec);
		cli.o_int<uint16_t>(IOSLAVES_MINECRAFT_PROTO_VERS);
		bool is_a_gran_master = cli.i_bool();
		std::string s_servid = cli.i_str();
		minecraft::op_code opp = (minecraft::op_code)cli.i_char();
		
		if (s_servid.empty()) {
			switch (opp) {
				
				case minecraft::op_code::REFUSE_OPTION: {
					__log__(log_lvl::LOG, "COMM", logstream << "Master wants to toggle refuse option");
					minecraft::refuse_mode = cli.i_bool();
					cli.o_char((char)ioslaves::answer_code::OK);
					__log__(log_lvl::IMPORTANT, NULL, logstream << (minecraft::refuse_mode?"Refusing":"Accepting") << " servers from now.");
				} break;
				
				default:
					__log__(log_lvl::ERROR, "COMM", logstream << "Bad operation '" << (char)opp << "'");
					cli.o_char((char)ioslaves::answer_code::OP_NOT_DEF);
					
			}
			return;
		}
		
		if (!ioslaves::validateServiceName(s_servid)) {
			__log__(log_lvl::ERROR, "PARAM", logstream << "'" << s_servid << "' is not a valid server name");
			cli.o_char((char)ioslaves::answer_code::SECURITY_ERROR);
			return;
		}
		
		pthread_mutex_handle _mutex_handle_ (&minecraft::servs_mutex);
		
			// Report server stop-reports to master, if able to handle it
		if (opp != minecraft::op_code::FIX_MAP) 
		for (auto it = minecraft::servs_stopped.begin(); it != minecraft::servs_stopped.end();) {
			minecraft::serv_stopped& ss = *it;
			if (s_servid == ss.serv or is_a_gran_master) {
				__log__(log_lvl::IMPORTANT, "COMM", logstream << "Reporting stop of server '" << ss.serv << "' to master");
				cli.o_char((char)ioslaves::answer_code::WANT_REPORT);
				cli.o_str(ss.serv);
				cli.o_char((char)ss.why);
				cli.o_bool(ss.gracefully);
				cli.o_bool((bool)minecraft::servs.count(ss.serv));
				cli.o_str(ss.map_to_save);
				bool accept = cli.i_bool();
				if (accept) {
					if (not ss.map_to_save.empty()) {
						block_as_mcjava();
						minecraft::compressAndSend(cli, ss.serv, ss.map_to_save, true);
					}
					auto p_it = it++; minecraft::servs_stopped.erase(p_it);
				} else 
					++it;
			}
		}
		switch (opp) {
				
				// Passing client to server thread
			case minecraft::op_code::COMM_SERVER: {
				cli.o_char((char)ioslaves::answer_code::OK);
				__log__(log_lvl::LOG, "COMM", logstream << "Master wants to connect with server '" << s_servid << "' thread");
				try {
					minecraft::serv* s = minecraft::servs.at(s_servid);
					socketxx::io::simple_socket<socketxx::base_fd> s_comm(socketxx::base_fd(s->s_sock_comm, SOCKETXX_MANUAL_FD));
					s_comm.o_char((char)minecraft::internal_serv_op_code::CHAT_WITH_CLIENT);
					s_comm.o_sock(cli);
				} catch (const std::out_of_range) {
					__log__(log_lvl::ERROR, "COMM", logstream << "Server '" << s_servid << "' not found");
					cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
				}
			} break;
			
				// Start server
			case minecraft::op_code::START_SERVER: {
				__log__(log_lvl::LOG, "COMM", logstream << "Master wants to start server '" << s_servid << "'");
				cli.o_char((char)ioslaves::answer_code::OK);
				_mutex_handle_.soon_unlock();
				minecraft::startServer(cli, s_servid);
			} break;
			
				// Stop server
			case minecraft::op_code::STOP_SERVER: {
				__log__(log_lvl::LOG, "COMM", logstream << "Master wants to stop server '" << s_servid << "'");
				try {
					minecraft::serv* s = minecraft::servs.at(s_servid);
					cli.o_char((char)ioslaves::answer_code::OK);
					minecraft::stopServer(cli, s, _mutex_handle_);
				} catch (const std::out_of_range) {
					__log__(log_lvl::ERROR, "COMM", logstream << "Server '" << s_servid << "' not found");
					cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
				}
			} break;
				
				// Kill server
			case minecraft::op_code::KILL_SERVER: {
				__log__(log_lvl::LOG, "COMM", logstream << "Master wants to kill server '" << s_servid << "'");
				try {
					minecraft::serv* s = minecraft::servs.at(s_servid);
					cli.o_char((char)ioslaves::answer_code::OK);
					socketxx::io::simple_socket<socketxx::base_fd> s_comm(socketxx::base_fd(s->s_sock_comm, SOCKETXX_MANUAL_FD));
					s_comm.o_char((char)minecraft::internal_serv_op_code::KILL_JAVA);
					__log__(log_lvl::DONE, NULL, "Kill order sent to thread");
					cli.o_char((char)ioslaves::answer_code::OK);
				} catch (const std::out_of_range) {
					__log__(log_lvl::ERROR, "COMM", logstream << "Server '" << s_servid << "' not found");
					cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
				}
			} break;
			
				// Fix / Unfix a world
			case minecraft::op_code::FIX_MAP: {
				cli.o_char((char)ioslaves::answer_code::OK);
				std::string map = cli.i_str();
				bool want_fixed = cli.i_bool();
				__log__(log_lvl::LOG, "COMM", logstream << "Master wants to " << (want_fixed?"enable":"disable") << " fix option for world '" << map << "' for server '" << s_servid << "'");
				try {
					block_as_mcjava();
					std::string dir = _S( MINECRAFT_SRV_DIR,"/mc_",s_servid );
					r = ::access(dir.c_str(), X_OK);
					if (r == -1) {
						__log__(log_lvl::ERROR, "COMM", logstream << "Server '" << s_servid << "' not found in filesystem");
						cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
						break;
					}
					dir = _S( dir,'/',map );
					r = ::access(dir.c_str(), X_OK);
					if (r == -1) {
						__log__(log_lvl::ERROR, "SERV", logstream << "World '" << map << "' on server '" << s_servid << "' not found");
						cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
						break;
					}
					std::string fixed_map_file = _S( dir,"/fixed_map" );
					bool currently_fixed = not ( ioslaves::infofile_get(fixed_map_file.c_str(), true).empty() );
					if (currently_fixed == want_fixed) {
						__log__(log_lvl::SEVERE, "SERV", logstream << "Fix order contradictory with local fix state ! Manual intervention needed.");
						cli.o_char((char)ioslaves::answer_code::BAD_TYPE);
						break;
					}
					if (want_fixed == true) {
						__log__(log_lvl::IMPORTANT, "SERV", logstream << "Fixing world '" << map << "' of server '" << s_servid << "'...", LOG_WAIT, &l);
						time_t lastsavetime = minecraft::lastsaveTimeFile(_S( MINECRAFT_SRV_DIR,"/mc_",s_servid,'/',map ), false);
						cli.o_char((char)ioslaves::answer_code::OK);
						cli.o_int<uint64_t>(lastsavetime);
						if ((ioslaves::answer_code)cli.i_char() != ioslaves::answer_code::OK) {
							__log__(log_lvl::ERROR, "SERV", "Master has invalidated fix order !");
							break;
						}
						ioslaves::infofile_set(fixed_map_file.c_str(), "DO NOT DELETE");
						cli.o_char((char)ioslaves::answer_code::OK);
					} else {
						__log__(log_lvl::IMPORTANT, "SERV", logstream << "Unfixing world '" << map << "' of server '" << s_servid << "'...", LOG_WAIT, &l);
						if (minecraft::servs.find(s_servid) != minecraft::servs.end() and minecraft::servs.find(s_servid)->second->s_map == map) {
							__log__(log_lvl::NOTICE, NULL, logstream << "Server '" << s_servid << "' is running with this world : can't unfix");
							cli.o_char((char)ioslaves::answer_code::BAD_STATE);
							return;
						}
						cli.o_char((char)ioslaves::answer_code::OK);
						__log__(log_lvl::LOG, NULL, logstream << "Invalidate FTP sessions for server '" << s_servid << "'");
						minecraft::ftp_del_sess_for_serv(s_servid, 0);
						cli.o_char((char)ioslaves::answer_code::OK);
						__log__(log_lvl::IMPORTANT, NULL, logstream << "Saving world '" << map << "' of server '" << s_servid << "'...");
						bool sent = minecraft::compressAndSend(cli, s_servid, map, false);
						if (not sent) {
							__log__(log_lvl::SEVERE, NULL, logstream << "Master hasn't accepted world save : can't unfix");
							cli.o_char((char)ioslaves::answer_code::DENY);
							return;
						}
						ioslaves::infofile_set(fixed_map_file.c_str(), "");
						cli.o_char((char)ioslaves::answer_code::OK);
					}
					__log__(log_lvl::DONE, "SERV", "Done", LOG_ADD, &l);
				} catch (const std::exception& e) {
					__log__(log_lvl::SEVERE, NULL, logstream << "Error while (un)fixing world : " << e.what());
					cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR);
				}
			} break;
			
				// Send stats to client (status, running map, start time, players, port, list of server maps)
			case minecraft::op_code::SERV_STAT: {
				logl_t l;
				__log__(log_lvl::_DEBUG, "COMM", logstream << "Master wants to get status of server '" << s_servid << "'", LOG_WAIT, &l);
				cli.o_char((char)ioslaves::answer_code::OK);
				minecraft::serv* s = NULL;
				try {
					s = minecraft::servs.at(s_servid);
					__log__(log_lvl::_DEBUG, "COMM", ": Running", LOG_ADD, &l);
					cli.o_bool(true);
					if (cli.i_bool()) {
						in_port_t port = s->s_port;
						cli.o_bool(s->s_is_perm_map);
						cli.o_str(s->s_map);
						time_t start_time = ::time(NULL) - (::iosl_time() - s->s_start_iosl_time);
						cli.o_int<uint64_t>(start_time);
						socketxx::io::simple_socket<socketxx::base_fd> s_comm(socketxx::base_fd(s->s_sock_comm, SOCKETXX_MANUAL_FD));
						s_comm.o_char((char)minecraft::internal_serv_op_code::GET_PLAYER_LIST);
						_mutex_handle_.soon_unlock();
						ioslaves::answer_code o = (ioslaves::answer_code)s_comm.i_char();
						if (o == ioslaves::answer_code::OK) {
							cli.o_int<int32_t>(s_comm.i_int<int16_t>()); // # of players
							cli.o_int<uint32_t>(s_comm.i_int<uint32_t>()); // 0 players since
						} else {
							cli.o_int<int32_t>(-1);
							cli.o_int<uint32_t>(0);
						}
						cli.o_int<in_port_t>(port);
					}
				} catch (const std::out_of_range) {
					__log__(log_lvl::_DEBUG, "COMM", ": Not running", LOG_ADD, &l);
					cli.o_bool(false);
				}
					// Send map list (without running map) with their last-save-time for master syncing, and send map save if needed
				__log__(log_lvl::_DEBUG, "FILES", logstream << "List maps...", LOG_WAIT, &l);
				std::vector<std::tuple<std::string,time_t,bool>> serv_maps;
				try {
					block_as_mcjava();
					std::string global_serv_dir = _S( MINECRAFT_SRV_DIR,"/mc_",s_servid );
					DIR* dir = ::opendir(global_serv_dir.c_str());
					if (dir == NULL) {
						if (errno == ENOENT) {
							cli.o_int<uint32_t>(0);
							break;
						}
						throw xif::sys_error("can't open global server dir for listing maps");
					}
					dirent* dp, *dentr = (dirent*) ::malloc(
						(size_t)offsetof(struct dirent, d_name) + std::max(sizeof(dirent::d_name), (size_t)::fpathconf(dirfd(dir),_PC_NAME_MAX)) +1
					);
					RAII_AT_END({ 
						::closedir(dir);
						::free(dentr);
					});
					int rr;
					while ((rr = ::readdir_r(dir, dentr, &dp)) != -1 and dp != NULL) {
						std::string map = std::string(dentr->d_name);
						if (ioslaves::validateName(map) and not (s != NULL and s->s_map == map)) {
							std::string lastsavetime_path = _S( MINECRAFT_SRV_DIR,"/mc_",s_servid,'/',map );
							r = ::access(_s(lastsavetime_path,"/lastsave"), R_OK);
							time_t lastsave = 0;
							if (r == 0) 
								lastsave = minecraft::lastsaveTimeFile(lastsavetime_path.c_str(), false);
							bool fixed = not ioslaves::infofile_get(_s( MINECRAFT_SRV_DIR,"/mc_",s_servid,'/',map,"/fixed_map" ), true).empty();
							__log__(log_lvl::_DEBUG, "FILES", logstream << map << ":" << lastsave << (fixed?" (fix)":""), LOG_ADD|LOG_WAIT, &l);
							serv_maps.push_back(std::make_tuple(map,lastsave,fixed));
						}
					}
					if (rr == -1)
						throw xif::sys_error("map listing in server folder : readdir_r");
				} catch (const std::exception& e) {
					__log__(log_lvl::ERROR, "FILES", logstream << "Error while listing maps of server : " << e.what());
				}
				cli.o_int<uint32_t>((uint32_t)serv_maps.size());
				for (decltype(serv_maps)::const_reference t : serv_maps) {
					cli.o_str(std::get<0>(t));
					cli.o_int<uint64_t>(std::get<1>(t));
					cli.o_bool(std::get<2>(t));
					ioslaves::answer_code o = (ioslaves::answer_code)cli.i_char();
					if (o == ioslaves::answer_code::WANT_GET) {
						block_as_mcjava();
						minecraft::compressAndSend(cli, s_servid, std::get<0>(t), true);
					}
				}
			} break;
			
				// Transform a temp map into a permanent map (server folder will not be deleted)
			case minecraft::op_code::PERMANENTIZE: {
				logl_t l;
				__log__(log_lvl::LOG, "COMM", logstream << "Master wants to permanentize the map on server '" << s_servid << "'.", LOG_WAIT, &l);
				try {
					minecraft::serv* s = minecraft::servs.at(s_servid);
					if (s->s_is_perm_map) {
						__log__(log_lvl::NOTICE, "COMM", logstream << "Map '" << s->s_map << "' is already permanent !");
						cli.o_char((char)ioslaves::answer_code::BAD_TYPE);
					} else {
						cli.o_char((char)ioslaves::answer_code::OK);
						cli.o_str(s->s_map);
						s->s_is_perm_map = true;
						__log__(log_lvl::DONE, NULL, "Done !", LOG_ADD, &l);
						cli.o_char((char)ioslaves::answer_code::OK);
					}
				} catch (const std::out_of_range) {
					__log__(log_lvl::ERROR, "COMM", logstream << "Server '" << s_servid << "' not found");
					cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
				}
			} break;
			
				// Delete a map folder (if not used)
			case minecraft::op_code::DELETE_MAP: {
				cli.o_char((char)ioslaves::answer_code::OK);
				std::string map = cli.i_str();
				logl_t l;
				__log__(log_lvl::LOG, "COMM", logstream << "Master wants to delete map '" << map << "' on server '" << s_servid << "'.", LOG_WAIT, &l);
				if (minecraft::servs.find(s_servid) != minecraft::servs.end() and minecraft::servs.find(s_servid)->second->s_map == map) {
					__log__(log_lvl::NOTICE, "COMM", logstream << "Server is running with this map");
					cli.o_char((char)ioslaves::answer_code::BAD_STATE);
					return;
				}
				std::string folder_path = _S( MINECRAFT_SRV_DIR,"/mc_",s_servid,'/',map );
				if (::access(folder_path.c_str(), F_OK) == -1) {
					__log__(log_lvl::ERROR, "COMM", logstream << "Folder not found");
					cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
					return;
				}
				if (not ioslaves::infofile_get(_s( folder_path,"/fixed_map" ), true).empty() ) {
					__log__(log_lvl::ERROR, "COMM", logstream << "World is fixed");
					cli.o_char((char)ioslaves::answer_code::DENY);
					return;
				}
				try {
					asroot_block();
					ioslaves::rmdir_recurse(folder_path.c_str());
					cli.o_char((char)ioslaves::answer_code::OK);
				} catch (const xif::sys_error& e) {
					__log__(log_lvl::ERROR, NULL, logstream << "Failed to delete map folder : " << e.what());
					cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR);
				}
			} break;
				
				// Send world save
			case minecraft::op_code::SAVE_MAP: {
				cli.o_char((char)ioslaves::answer_code::OK);
				std::string map = cli.i_str();
				logl_t l;
				__log__(log_lvl::LOG, "COMM", logstream << "Master wants to retrieve save of world '" << map << "' of server '" << s_servid << "'.", LOG_WAIT, &l);
				std::string folder_path = _S( MINECRAFT_SRV_DIR,"/mc_",s_servid,'/',map );
				if (::access(folder_path.c_str(), F_OK) == -1) {
					__log__(log_lvl::ERROR, "COMM", logstream << "Folder not found");
					cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
					return;
				}
				cli.o_char((char)ioslaves::answer_code::OK);
				try {
					block_as_mcjava();
					bool sent = minecraft::compressAndSend(cli, s_servid, map, false);
					if (not sent) 
						__log__(log_lvl::ERROR, NULL, logstream << "Failed to send world save.");
				} catch (const std::exception& e) {
					__log__(log_lvl::ERROR, "COMM", logstream << "World save sending has failed : " << e.what());
					try { cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR); } catch (...) {}
				}
			} break;
			
				// Create a new FTP session
			case minecraft::op_code::FTP_SESSION: {
				__log__(log_lvl::LOG, "COMM", logstream << "Master wants to create a new ftp session for server '" << s_servid << "' with currently running map");
				try {
					minecraft::serv* s = minecraft::servs.at(s_servid);
					cli.o_char((char)ioslaves::answer_code::OK);
					cli.o_str(s->s_map);
					std::string username = cli.i_str();
					std::string md5passwd = cli.i_str();
					time_t validity = cli.i_int<uint32_t>();
					try {
						minecraft::ftp_register_user(username, md5passwd, s_servid, s->s_map, validity);
						cli.o_char((char)ioslaves::answer_code::OK);
						cli.o_str(minecraft::ftp_serv_addr);
					} catch (const ioslaves::req_err& re) {
						cli.o_char((char)re.answ_code);
					}
				} catch (const std::out_of_range) {
					__log__(log_lvl::ERROR, "COMM", logstream << "Server '" << s_servid << "' not running");
					cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
				}
			} break;
			
			default:
				__log__(log_lvl::ERROR, "COMM", logstream << "Bad operation '" << (char)opp << "'");
				cli.o_char((char)ioslaves::answer_code::OP_NOT_DEF);
		}
	} catch (const socketxx::error& e) {
		__log__(log_lvl::ERROR, "COMM", logstream << "Network error : " << e.what());
	}
}


	/** -------------------------------	**/
	/**         Utility functions       	**/
	/** -------------------------------	**/

	// Should always be running as euid=mcjava
inline void assert_mcjava () {
#ifdef __linux__
	uid_t euid = ::getegid();
	if (euid != minecraft::java_user_id) 
		throw std::logic_error("should be running as mcjava !");
#endif
}
#ifndef __linux__
	#define java_user_id -1
	#define java_group_id -1
#endif

/// Transfer and map functions

// Read/write the last-save-time file on server folder
time_t minecraft::lastsaveTimeFile (std::string path, bool set) {
	assert_mcjava();
	fd_t file; ssize_t rs;
	time_t lastsave = 0;
	timeval utc_time;
	::gettimeofday(&utc_time, NULL);
	path += "/lastsave"; 
	file = ::open(path.c_str(), (set ? O_CREAT|O_WRONLY|O_TRUNC : O_RDONLY), S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (file == INVALID_HANDLE) 
		throw xif::sys_error(logstream << "failed to open server to " << (set?"set":"get") << " folder last-save-time file (" << path << ")" << logstr);
	RAII_AT_END_L( ::close(file); );
	const size_t sz = sizeof(time_t)*2;
	if (set) {
		lastsave = utc_time.tv_sec;
		std::string buf = ::ixtoap(utc_time.tv_sec,sz, IX_HEX);
		rs = ::write(file, buf.c_str(), sz);
		if (rs != sz) 
			throw xif::sys_error("write last-save-time file");
	} else {
		char buf[sz];
		rs = ::read(file, buf, sz);
		if (rs != sz) 
			throw xif::sys_error("error while reading server folder last-save-time", (rs==-1?"error":"size error"));
		try {
			lastsave = ::atoix<time_t>(std::string(buf,sz), IX_HEX);
		} catch (const std::runtime_error& re) { lastsave = 0; }
		if (lastsave == 0) {
			throw xif::sys_error("server folder last-save-time", "null or invalid number"); }
		if (lastsave > utc_time.tv_sec) 
			throw xif::sys_error("server folder last-save-time", "is in future !");
	}
	return lastsave;
}

// Unzip archive
void minecraft::unzip (const char* file, const char* in_dir, const char* expected_dir_name) {
	assert_mcjava();
	logl_t l;
	__log__(log_lvl::_DEBUG, "FILES", logstream << "Unzipping file (expecting '" << expected_dir_name << "')... ", LOG_WAIT, &l);
	int r;
	std::string expected_dir = _S( in_dir,'/',expected_dir_name );
	r = ::access(expected_dir.c_str(), F_OK);
	if (r == 0) {
		__log__(log_lvl::WARNING, "FILES", logstream << "Expected dir ('" << expected_dir_name << "') already exists. Deleting it.");
		{ asroot_block();
			ioslaves::rmdir_recurse(expected_dir.c_str()); }
	}
	r = ::access(file, R_OK);
	if (r == -1) throw xif::sys_error("unzip() : archive file not found");
	{ sigchild_block(); asroot_block();
		int unzip_r = 
			ioslaves::exec_wait("unzip", {"-nq", file, "-d", in_dir}, NULL, java_user_id, java_group_id);
		if (unzip_r != 0) 
			throw xif::sys_error("unzip command failed", _s("return code ",::ixtoa(unzip_r)));
	}
	r = ::access(expected_dir.c_str(), X_OK);
	if (r == -1) throw xif::sys_error("unzip command failed", "expected dir not found or unreachable");
	__log__(log_lvl::DONE, "FILES", "Done", LOG_ADD, &l);
}

// Transfer archives or files
void minecraft::transferAndExtract (socketxx::io::simple_socket<socketxx::base_socket> sock, minecraft::transferWhat what, std::string name, std::string parent_dir, bool alt) {
	assert_mcjava();
	int r;
	sock.o_char((char)ioslaves::answer_code::WANT_GET);
	sock.o_char((char)what);
	if (what == minecraft::transferWhat::BIGFILE) 
		sock.o_str(name);
	else if (what == minecraft::transferWhat::JAR)
		sock.o_bool(alt);
	if (!sock.i_bool()) 
		throw ioslaves::req_err(ioslaves::answer_code::DENY, "FILES", logstream << "Master refused sending file '" << name << "'");
	std::string tempfile_name;
	logl_t l;
	__log__(log_lvl::LOG, "FILES", logstream << "Downloading file '" << name << "' of type '" << (char)what << "' from master...", LOG_WAIT, &l);
	if (what == minecraft::transferWhat::MAP || what == minecraft::transferWhat::JAR || what == minecraft::transferWhat::BIGFILE) {
		tempfile_name = _S( parent_dir,'/',name );
		mode_t fmod = (what == minecraft::transferWhat::MAP) ? (mode_t)0640 : (mode_t)0644;
		fd_t tempfd = ::open(tempfile_name.c_str(), O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW, fmod);
		if (tempfd == -1)
			throw xif::sys_error("failed to open destination file for transferring");
		try {
			sock.i_file(tempfd);
		} catch (...) {
			::close(tempfd);
			::unlink(tempfile_name.c_str());
			throw;
		}
		::close(tempfd);
	} else {
		tempfile_name = sock.i_file(_S( MINECRAFT_SRV_DIR,"/ioslaves-mc-trsf" ));
	}
	struct stat file_stat;
	r = ::stat(tempfile_name.c_str(), &file_stat);
	if (r == -1)
		throw xif::sys_error("failed to stat() file");
	__log__(log_lvl::DONE, "FILES", logstream << file_stat.st_size/1024 << " Kio Done", LOG_ADD|LOG_WAIT, &l);
	if (what == minecraft::transferWhat::MAP || what == minecraft::transferWhat::JAR || what == minecraft::transferWhat::BIGFILE) {
		__log__(log_lvl::LOG, "FILES", logstream << "- Stored in cache", LOG_ADD, &l);
	} else {
		minecraft::unzip(tempfile_name.c_str(), parent_dir.c_str(), name.c_str());
		r = ::unlink(tempfile_name.c_str());
	}
}

// Cleanup, zip and send server folder to master
bool minecraft::compressAndSend (socketxx::io::simple_socket<socketxx::base_socket> sock, std::string servname, std::string mapname, bool async) {
	assert_mcjava();
	int r;
	std::string serv_dir_path = _S( MINECRAFT_SRV_DIR,"/mc_",servname );
	std::string map_dir_path = _S( serv_dir_path,'/',mapname );
	time_t lastsavetime = lastsaveTimeFile(map_dir_path, false);
	logl_t l;
	__log__(log_lvl::LOG, "FILES", MCLOGCLI(servname) << "Uploading save of map '" << mapname << "' to master with last-save-time " << lastsavetime << "...", LOG_WAIT, &l);
	sock.o_int<int64_t>(lastsavetime);
	if (sock.i_bool() == false) {
		__log__(log_lvl::WARNING, "FILES", logstream << "Master refused retrieving map save !");
		return false;
	}
	std::string fpath = _S( "/tmp/ioslaves-minecraft-send-",::ixtoa(::rand()),"-",servname,"-",mapname,".zip" );
	__log__(log_lvl::LOG, "FILES", logstream << "Zipping dir '" << mapname << "'...", LOG_WAIT, &l);
	r = ::unlink(_s( map_dir_path,"/server.log" ));
	r = ::unlink(_s( map_dir_path,"/server.properties" ));
	try {  ioslaves::rmdir_recurse(_s( map_dir_path+"/crash-reports" )); } catch (...) {}
	try {  ioslaves::rmdir_recurse(_s( map_dir_path+"/logs" ));          } catch (...) {}
	{ sigchild_block(); asroot_block();
		int zip_r = 
			ioslaves::exec_wait("zip", {"-rq", "-6", fpath, mapname}, serv_dir_path.c_str(), java_user_id, java_group_id);
		if (zip_r != 0) 
			throw xif::sys_error("zip command failed", _s("return code ",::ixtoa(zip_r)));
	}
	r = ::access(fpath.c_str(), F_OK);
	if (r == -1) throw xif::sys_error("zip command failed", "final archive not found");
	__log__(log_lvl::DONE, "FILES", "Done", LOG_ADD, &l);
	if (async) {
		#warning TO DO
		//return;
	}
	struct stat zip_stat;
	r = ::stat(fpath.c_str(), &zip_stat);
	if (r == -1) throw xif::sys_error("file send : stat() failed");
	__log__(log_lvl::LOG, "FILES", logstream << "Uploading " << zip_stat.st_size/1024 << "Kio...", LOG_WAIT, &l);
	sock.o_file(fpath.c_str());
	r = ::unlink(fpath.c_str());
	__log__(log_lvl::DONE, "FILES", "Done", LOG_ADD, &l);
	return true;
}

// Delete map folder
void minecraft::deleteMapFolder (minecraft::serv* s) {
	__log__(log_lvl::NOTICE, "FILES", MCLOGSCLI(s) << "Deleting server folder of map '" << s->s_map << "'...");
	std::string path = _S( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map );
	ioslaves::rmdir_recurse(path.c_str());
}

// Delete lock files
void minecraft::deleteLckFiles (std::string in_dir) {
	int r;
	DIR* dir = ::opendir(in_dir.c_str());
	RAII_AT_END_L( ::closedir(dir) );
	if (dir == NULL) 
		throw xif::sys_error("deleteLckFiles : can't open dir");
	dirent* dp = NULL;
	while ((dp = ::readdir(dir)) != NULL) {
		if (std::string(dp->d_name).find(".lck") != std::string::npos) {
			r = ::unlink(_s( in_dir,'/',dp->d_name ));
			if (r == -1)
				throw xif::sys_error(_S("failed to delete ",dp->d_name));
			__ldebug__(NULL, logstream << "Deleted " << dp->d_name);
		}
	}
}

// Copy server template directory
void minecraft::cpTplDir (const char* tplDir, std::string working_dir) {
	assert_mcjava();
	__ldebug__("FILES", logstream << "Copying template folder");
	int r;
	{ sigchild_block(); asroot_block();
		int cp_r = 
			ioslaves::exec_wait("cp", {"-R", tplDir, working_dir}, NULL, java_user_id, java_group_id);
		if (cp_r != 0) 
			throw xif::sys_error("cp command failed", _s("return code ",::ixtoa(cp_r)));
	}
	r = ::access(working_dir.c_str(), X_OK);
	if (r == -1) 
		throw xif::sys_error("cp failed", "excepted dir not found or unreachable");
}

// Template files : *.xx.in => *.xx replacing %KEY% with value of hashlist["KEY"]
void minecraft::processTemplateFile (const char* fpath, std::map<std::string,std::string> hashlist, std::string header) {
	std::string fpath_final = fpath;
	fpath_final = fpath_final.substr(0, fpath_final.find(".in"));
	FILE* f = ::fopen(fpath, "r");
	if (f == NULL)
		throw xif::sys_error(_S("can't open template file ",fpath));
	FILE* ff = ::fopen(fpath_final.c_str(), "w");
	if (ff == NULL)
		throw xif::sys_error(_S("can't open dest file for untemplating ",fpath_final));
	std::string keybuf;
	bool keymode = false;
	int c;
	if (not header.empty())
		if (::fwrite(header.c_str(), header.length(), 1, ff) != 1)
			goto __werror;
	while ((c = ::fgetc(f)) != EOF) {
		if (keymode) {
			if (c == '%') {
				try {
					keybuf = hashlist.at(keybuf);
				} catch (...) { goto __cancelkey; }
				goto __writeback;
			} else if (not ::isupper(c))
				goto __cancelkey;
			else 
				keybuf += (char)c;
		} else {
			if (c == '%') 
				keymode = true;
			else {
				c = ::fputc(c, ff); 
				if (c == EOF) goto __werror;
			}
		}
		continue;
	__cancelkey:
		keybuf.insert(0, (size_t)1, '%') += (char)c;
		goto __writeback;
	__writeback:
		if (not keybuf.empty())
			if (::fwrite(keybuf.c_str(), keybuf.length(), 1, ff) != 1)
				goto __werror;
		keybuf.clear();
		keymode = false;
		continue;
	__werror:
		::fclose(f); ::fclose(ff);
		throw xif::sys_error("untemplating : can't write to dest file");
	}
	::fclose(f); ::fclose(ff);
}

std::vector<minecraft::_BigFiles_entry> minecraft::getBigFilesIndex (std::string serv_path) {
	int r;
	std::vector<minecraft::_BigFiles_entry> list;
	std::string findexpath = serv_path+"/bigfiles.ioslmc";
	r = ::access(findexpath.c_str(), R_OK);
	if (r != -1) {
		FILE* f  = ::fopen(findexpath.c_str(), "r");
		int c;
		bool fn = false;
		char type_c = 0;
		_BigFiles_entry entry;
		while ((c = ::fgetc(f)) != EOF) {
			if (fn == false) {
				if (c == '\n') { if (entry.name.empty()) continue; else goto __error; }
				if (c == '/') goto __error;
				if (c == '\t') fn = true;
				else entry.name += c;
			}
			if (fn == true) {
				if (entry.final_path.empty()) {
					if (c == '\t') 
						continue;
					else if (type_c == 0) 
						type_c = c;
					else if (c == '/') 
						entry.final_path += '/';
					else 
						goto __error;
				} else {
					if (c == '\t') goto __error;
					if (c == '\n') {
						fn = false;
					__puush:
						if (type_c == '=') 
							entry.final_path = serv_path + entry.final_path;
						else if (type_c == '>') 
							entry.final_path = serv_path + entry.final_path + entry.name;
						else goto __error;
						list.push_back(entry);
						entry = _BigFiles_entry();
						type_c = 0;
					}
					else entry.final_path += c;
				}
			}
		}
		if (not entry.name.empty()) {
			if (entry.final_path.empty()) goto __error;
			goto __puush;
		}
		::fclose(f);
		return list;
	__error:
		__log__(log_lvl::WARNING, "FILES", logstream << "Error while decoding big-files index file");
		::fclose(f);
		list.clear();
	}
	return list;
}

	/** ------------------------------------	**/
	/**       Server launch and thread      	**/
	/** ------------------------------------	**/

#ifndef __linux__
	#undef java_user_id
	#undef java_group_id
#endif

		/// Start procedure
void minecraft::startServer (socketxx::io::simple_socket<socketxx::base_socket> cli, std::string servid) {
	int r;
	minecraft::serv* s = new minecraft::serv;
	s->s_servid = servid;
	
		// Auto delete server on error/failure : delete structure, temp map folder, reset effective uid
	struct _autodelete_serv {
		minecraft::serv* s = NULL;
		bool close_port = false;
		bool can_del_folder = false;
		_autodelete_serv (minecraft::serv* s) : s(s), can_del_folder(false) {}
		~_autodelete_serv () {
			ioslaves::api::euid_switch(0,0);
			if (s != NULL) { 
				if (can_del_folder) try { minecraft::deleteMapFolder(s); } catch (...) {}
				if (close_port) try { (*ioslaves::api::close_port)(s->s_port, 1, true); } catch (...) {}
				pthread_mutex_handle_lock(minecraft::servs_mutex);
				delete s;
			}
			ioslaves::api::euid_switch(-1,-1);
		}
	} __autodelete_serv(s);
	
	try {
		
			// Get infos : server name, server jar (distro+ver), needed RAM and running time, permanent or temp map, UTC last-same-time on master, early liveconsole option, autoshutdown, and minecraft options
		s->s_serv_type = (minecraft::serv_type)cli.i_char();
		s->s_mc_ver = ioslaves::version(cli.i_str(),true);
		s->s_megs_ram = cli.i_int<uint16_t>();
		s->s_is_perm_map = cli.i_bool();
		bool start_temp_perm;
		if (not s->s_is_perm_map)
			start_temp_perm = cli.i_bool();
		s->s_delay_noplayers = cli.i_int<uint32_t>();
		s->s_viewdist = cli.i_int<uint8_t>();
		if (s->s_viewdist > minecraft::max_viewdist) s->s_viewdist = minecraft::max_viewdist;
		time_t s_running_time = cli.i_int<uint32_t>();
		time_t time_rest = *ioslaves::api::common_vars->shutdown_iosl_time - ::iosl_time();
		if (not minecraft::ignore_shutdown_time and *ioslaves::api::common_vars->shutdown_iosl_time != 0 and time_rest < s_running_time) 
			throw ioslaves::req_err(ioslaves::answer_code::LACK_RSRC, "SERV", MCLOGSCLI(s) << "Server wants ~" << s_running_time/60 << "min, but slave would shutdown in " << time_rest/60 << "min. " << "Refusing start request.", log_lvl::OOPS);
		if (minecraft::refuse_mode == true) 
			throw ioslaves::req_err(ioslaves::answer_code::LACK_RSRC, "SERV", MCLOGSCLI(s) << "Can't start server : refuse option activated.", log_lvl::OOPS);
		s->s_map = cli.i_str();
		if (!ioslaves::validateName(s->s_map)) 
			throw ioslaves::req_err(ioslaves::answer_code::SECURITY_ERROR, "PARAM", MCLOGSCLI(s) << "'" << s->s_map << "' is not a valid map name");
		time_t s_lastsavetime = (time_t)cli.i_int<int64_t>();
		bool early_console = cli.i_bool();
		s->s_port = cli.i_int<uint16_t>();
		size_t oth_ports_sz = cli.i_int<uint8_t>();
		for (size_t i = 0; i < oth_ports_sz; i++) {
			in_port_t port = cli.i_int<uint16_t>();
			s->s_oth_ports.push_back(port);
		}
		
			// Check free memory
		xif::polyvar::map sysinfo = *ioslaves::api::common_vars->system_stat;
		int16_t usable_mem = (float)(int16_t)sysinfo["mem_usable"] + MC_SWAP_FACTOR*(float)(int16_t)sysinfo["mem_swap"];
		if (s->s_megs_ram < MC_MIN_SERV_RAM) s->s_megs_ram = MC_MIN_SERV_RAM;
		if (usable_mem < (int16_t)(s->s_megs_ram*MC_FREE_RAM_FACTOR)) 
			throw ioslaves::req_err(ioslaves::answer_code::LACK_RSRC, "SERV", MCLOGSCLI(s) << "Server needs at least " << s->s_megs_ram << "MB of memory, but only " << usable_mem << "MB of RAM is usable. " << "Refusing start request.", log_lvl::OOPS);
		if (s->s_megs_ram < 1024) s->s_megs_ram = 1024;
		
			// Delete remaining FTP sessions for server
		minecraft::ftp_del_sess_for_serv(s->s_servid, 0);
		
			// Check if the server is not already opened or opening 
			// Attribute and open port
		struct _autorm_opening_state {
			std::list<minecraft::serv*>::iterator it;
			bool is_set = false;
			~_autorm_opening_state () { if (is_set) { pthread_mutex_handle_lock(minecraft::servs_mutex); minecraft::opening_servs.erase(it); } }
		} __autorm_opening_state;
		
		{ pthread_mutex_handle_lock(minecraft::servs_mutex);
			std::string port_descr = _s("minecraft server ",servid);
			::srand((unsigned int)::time(NULL));
			int8_t itry = -0xF;
			if (s->s_port != 0) {
				if (s->s_port < MINECRAFT_PORT_RANGE_BEG) 
					throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "PORT", "Master-chosen port outside allowed range", log_lvl::ERROR);
				itry = MINECRAFT_PORT_RANGE_SZ-1;
				goto __test_port;
			}
		__new_port:
			if (++itry == MINECRAFT_PORT_RANGE_SZ)
				throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "PORT", "Port range entierly used !", log_lvl::SEVERE);
			s->s_port = ::rand()%MINECRAFT_PORT_RANGE_SZ + MINECRAFT_PORT_RANGE_BEG;
		__test_port:
			if (minecraft::servs.find(servid) != minecraft::servs.end())
				throw ioslaves::req_err(ioslaves::answer_code::BAD_STATE, "SERV", MCLOGSCLI(s) << "Server already opened", log_lvl::OOPS);
			for (std::pair<std::string,minecraft::serv*> p : minecraft::servs) {
				if (p.second->s_port == s->s_port) 
					goto __new_port;
			}
			for (minecraft::serv* oth_s : minecraft::opening_servs) {
				if (oth_s->s_servid == servid) 
					throw ioslaves::req_err(ioslaves::answer_code::BAD_STATE, "SERV", MCLOGSCLI(s) << "Server already opening", log_lvl::OOPS);
				if (oth_s->s_port == s->s_port)
					goto __new_port;
			}
			errno = 0;
			ioslaves::answer_code open_port_answ = (*ioslaves::api::open_port)(s->s_port, true, s->s_port, 1, port_descr);
			if (open_port_answ != ioslaves::answer_code::OK) {
				if (open_port_answ == ioslaves::answer_code::EXISTS or errno == 718 /*ConflictInMappingEntry*/)
					goto __new_port;
				throw ioslaves::req_err(ioslaves::answer_code::ERROR, "SERV", MCLOGSCLI(s) << "Failed to open port " << s->s_port << ioslaves::getAnswerCodeDescription(open_port_answ));
			}
			__autodelete_serv.close_port = true;
			__autorm_opening_state.it = minecraft::opening_servs.insert( minecraft::opening_servs.end(), s );
			__autorm_opening_state.is_set = true;
		}
		cli.o_char((char)ioslaves::answer_code::OK);
		cli.o_int<uint16_t>(s->s_port);
		
			// Great ! We have some work... Now we can send file requests to master
		__log__(log_lvl::MAJOR, NULL, logstream << "Starting '" << s->s_servid << "' server with " << (s->s_is_perm_map?"permanent":"temporary") << " map '" << s->s_map << "' on port " << s->s_port << " with jar '" << (char)s->s_serv_type << "' " << s->s_mc_ver.str());
		
			// Server folder and map
		block_as_mcjava();
		std::string global_serv_dir = _S( MINECRAFT_SRV_DIR,"/mc_",s->s_servid );
		r = ::mkdir(global_serv_dir.c_str(), (mode_t)0755);
		if (r == -1 and errno != EEXIST)
			throw xif::sys_error("can't create client server dir");
		std::string working_dir = s->s_wdir = _S( global_serv_dir,'/',s->s_map );
		struct stat wdir_stat;
		r = ::stat(working_dir.c_str(), &wdir_stat);
		if (r == -1) {
			if (errno != ENOENT)
				throw xif::sys_error(logstream << "can't stat(" << working_dir << ")" << logstr);
				// Temp map
			if (not s->s_is_perm_map) {
				__log__(log_lvl::LOG, "FILES", MCLOGSCLI(s) << "Loading temporary map...");
				minecraft::cpTplDir(MINECRAFT_TEMPLATE_SERVMAP_DIR, working_dir);
				__autodelete_serv.can_del_folder = true;
				std::string map_path = _S( MINECRAFT_TEMP_MAP_DIR,'/',s->s_map,".zip" );
				r = ::access(map_path.c_str(), R_OK);
				if (r == -1) {
					if (errno == ENOENT) {
						__log__(log_lvl::LOG, "FILES", logstream << "Downloading temporary map '" << s->s_map << "' from master...");
						minecraft::transferAndExtract(cli, minecraft::transferWhat::MAP, s->s_map+".zip", MINECRAFT_TEMP_MAP_DIR);
					}
					else throw xif::sys_error("testing for map in maps dir failed");
				}
				minecraft::unzip(map_path.c_str(), working_dir.c_str(), s->s_map.c_str());
					// Apply map specific properties
				std::string in_props_path = _S( working_dir,'/',s->s_map,"/server.properties.add" );
				std::string props_file_path = _S( working_dir,"/server.properties" );
				r = ::access(in_props_path.c_str(), R_OK);
				if (r != -1) {
					__log__(log_lvl::LOG, "FILES", logstream << "Applying map specific properties...");
					try {
						std::ofstream out_fs (props_file_path.c_str(), std::ios_base::binary | std::ios_base::app);
						std::ifstream in_fs (in_props_path.c_str(), std::ios_base::binary);
						out_fs.seekp(0, std::ios_base::end);
						out_fs << '\n' << in_fs.rdbuf();
					} catch (const std::ios::failure& e) {
						throw std::runtime_error(logstream << "failed to concatenate properties files : " << e.what() << logstr);
					}
				}
			} 
				// Permanent map : no folder found
			else {
				if (s_lastsavetime != MC_LASTSAVETIME_NOSAVE) {
					__log__(log_lvl::LOG, "FILES", MCLOGSCLI(s) << "No server folder found, getting latest from master...");
					minecraft::transferAndExtract(cli, minecraft::transferWhat::SERVFOLD, s->s_map, global_serv_dir);
				} else {
					__log__(log_lvl::LOG, "FILES", MCLOGSCLI(s) << "No server folder found on neither local or master save, creating new one...");
					minecraft::cpTplDir(MINECRAFT_TEMPLATE_SEV_DIR, working_dir);
					lastsaveTimeFile(working_dir, true);
				}
			}
		} else if (S_ISDIR(wdir_stat.st_mode)) {
			if (not s->s_is_perm_map) 
				throw ioslaves::req_err(ioslaves::answer_code::EXISTS, "FILES", MCLOGSCLI(s) << "Can't use temporary map '" << s->s_map << "' : a permanent server folder exists with this name", log_lvl::OOPS);
				// Permanent map folder found
				// Checking for .lck files
			{ DIR* dir = ::opendir(working_dir.c_str());
				RAII_AT_END_L( ::closedir(dir) );
				if (dir == NULL) 
					throw xif::sys_error("can't open working_dir for scanning");
				dirent* dp = NULL;
				while ((dp = ::readdir(dir)) != NULL) {
					if (std::string(dp->d_name).find("lck") != std::string::npos) 
						throw ioslaves::req_err(ioslaves::answer_code::BAD_STATE, "SERV", MCLOGSCLI(s) << "Server folder contains .lck files : server has crashed or seems to be running");
				}
			}
			bool fixedworld = not ( ioslaves::infofile_get(_s( working_dir,"/fixed_map" ), true).empty() );
			if (s_lastsavetime == MC_LASTSAVETIME_FORCE) {
				__log__(log_lvl::LOG, "FILES", MCLOGSCLI(s) << "Master wants to force sending of server folder. Sending the old one for backup...");
				cli.o_char((char)ioslaves::answer_code::WANT_SEND);
				minecraft::compressAndSend(cli, s->s_servid, s->s_map, true);
				minecraft::transferAndExtract(cli, minecraft::transferWhat::SERVFOLD, s->s_map, _S(MINECRAFT_SRV_DIR,"/mc_",s->s_servid));
			} else 
			if (not fixedworld) {
				time_t lastsavetime_map = 0;
				try {
					lastsavetime_map = lastsaveTimeFile(_S( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map ), false);
					__ldebug__("FILES", logstream << "Last-save-time local : " << lastsavetime_map << "; Last-save-time master : " << s_lastsavetime);
				} catch (const xif::sys_error& syserr) {
					if (syserr.errorno == ENOENT) {
						__log__(log_lvl::WARNING, "FILES", MCLOGSCLI(s) << "Server folder : last-save-time file not found. Setting as now.");
						lastsavetime_map = lastsaveTimeFile(_S( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map ), true);
					}
					else throw;
				}
				if (abs((int)(lastsavetime_map-s_lastsavetime)) < MINECRAFT_SERV_MASTER_MAX_DELAY_CONSIDERED_EQUAL) {
					__log__(log_lvl::_DEBUG, "FILES", MCLOGSCLI(s) << "Server folder is up-to-date with saved one on the master");
				}
				float diff_hours = (lastsavetime_map-s_lastsavetime)/3600.0f;
				if (lastsavetime_map < s_lastsavetime) {
					__log__(log_lvl::LOG, "FILES", MCLOGSCLI(s) << "Server folder is older by " << std::setprecision(2) << std::fixed << diff_hours << "h than master save, getting latest...");
					minecraft::transferAndExtract(cli, minecraft::transferWhat::SERVFOLD, s->s_map, _S(MINECRAFT_SRV_DIR,"/mc_",s->s_servid));
				}
				if (lastsavetime_map > s_lastsavetime) {
					if (s_lastsavetime == 0) 
						__log__(log_lvl::WARNING, "FILES", MCLOGSCLI(s) << "No save of server folder on master. Sending for backup...");
					else 
						__log__(log_lvl::WARNING, "FILES", MCLOGSCLI(s) << "Server folder is newer by " << std::setprecision(2) << std::fixed << diff_hours << "h than master save (maybe not saved last time or server crashed). Sending for backup...");
					cli.o_char((char)ioslaves::answer_code::WANT_SEND);
					minecraft::compressAndSend(cli, s->s_servid, s->s_map, false);
				}
			}
		} 
		else throw xif::sys_error(working_dir, "is not a directory");
		
			// Untemplating files, 'server.properties.in' is mandatory
		std::map<std::string,std::string> infos_keys;
		infos_keys["MAP"] = s->s_map;
		infos_keys["PORT"] = ::ixtoa(s->s_port);
		infos_keys["VIEWDIST"] = ::ixtoa(s->s_viewdist);
		infos_keys["CLI"] = s->s_servid;
		minecraft::processTemplateFile(_s( working_dir,"/server.properties.in" ), infos_keys, "# --- MODIFIEZ 'server.properties.in', PAS CE FICHIER ---\n\n");
		const char* tplsbeg[] = { /*"ops.txt",*/ NULL };
		for (size_t i = 0; tplsbeg[i] != NULL; ++i) {
			std::string fpth = _S( working_dir,"/",tplsbeg[i],".in" );
			r = ::access(fpth.c_str(), R_OK);
			if (r == 0) {
				minecraft::processTemplateFile(fpth.c_str(), infos_keys, "");
				r = ::unlink(fpth.c_str());
			}
		}
		
			// Handling big-files (chached big immutables files, like mods or plugins) -> create sym links in serv folder
		std::vector<minecraft::_BigFiles_entry> bigfiles = minecraft::getBigFilesIndex(working_dir);
		if (s->s_serv_type == minecraft::serv_type::FORGE or s->s_serv_type == minecraft::serv_type::CAULDRON)
			bigfiles.push_back( minecraft::_BigFiles_entry{ "forge_libs", _S(working_dir,"/libraries") } );
		if (s->s_serv_type == minecraft::serv_type::CAULDRON) 
			bigfiles.push_back( minecraft::_BigFiles_entry{ _S("cauldronbukkit-",s->s_mc_ver.str(),".jar") } );
		for (minecraft::_BigFiles_entry entry : bigfiles) {
			std::string file_path = _S( MINECRAFT_BIGFILES_DIR,'/',entry.name );
			r = ::access(file_path.c_str(), R_OK);
			if (r == -1) {
				__log__(log_lvl::LOG, "FILES", logstream << "Big-file '" << entry.name << "' not found here, getting from master...");
				minecraft::transferAndExtract(cli, minecraft::transferWhat::BIGFILE, entry.name, MINECRAFT_BIGFILES_DIR);
			}
			__log__(log_lvl::LOG, "FILES", logstream << "Creating symlink of big-file '" << entry.name << "'");
			if (entry.final_path.empty()) 
				entry.final_path = _S( working_dir,'/',entry.name );
			r = ::symlink(file_path.c_str(), entry.final_path.c_str());
			if (r == -1) {
				if (errno != EEXIST) throw xif::sys_error("failed to create symlink to big-file");
			}
		}
		
			// Jar
		std::string jar_name;
		std::string jar_path;
		if (s->s_serv_type == minecraft::serv_type::CUSTOM) {
			jar_path = _S( working_dir,'/',(jar_name=_S("mc_custom_",s->s_mc_ver.str(),".jar")) );
			r = ::access(jar_path.c_str(), R_OK);
			if (r == -1) {
				if (errno == ENOENT)
					throw ioslaves::req_err(ioslaves::answer_code::NOT_FOUND, "FILES", MCLOGSCLI(s) << "Custom jar `" << jar_name << "` not found in server folder", log_lvl::OOPS);
				else throw xif::sys_error("testing for custom .jar in server dir failed");
			}
		} else {
			const char* jar_prefix = NULL;
			     if (s->s_serv_type == minecraft::serv_type::VANILLA) jar_prefix = "mc_vanilla_";
			else if (s->s_serv_type == minecraft::serv_type::BUKKIT) jar_prefix = "mc_bukkit_";
			else if (s->s_serv_type == minecraft::serv_type::FORGE or s->s_serv_type == minecraft::serv_type::CAULDRON) {
				// Special treatment here : minecraft_server.jar will be patched by Forge and need to be in the folder
				if (s->s_serv_type == minecraft::serv_type::CAULDRON) jar_prefix = "mc_cauldron_";
				else if (s->s_serv_type == minecraft::serv_type::FORGE) jar_prefix = "mc_forge_";
				__log__(log_lvl::_DEBUG, "FILES", logstream << "Using forge -> Creating symlink to minecraft_server.jar");
				jar_path = _s( MINECRAFT_JAR_DIR,'/',(jar_name=_s("mc_vanilla_",s->s_mc_ver.strdigits(),".jar")) );
				r = ::access(jar_path.c_str(), R_OK);
				if (r == -1) {
					__log__(log_lvl::LOG, "FILES", logstream << "Getting jar " << jar_name << "...");
					minecraft::transferAndExtract(cli, minecraft::transferWhat::JAR, jar_name, MINECRAFT_JAR_DIR, true);
				}
				r = ::symlink( jar_path.c_str(), _s( working_dir,'/',"minecraft_server.",s->s_mc_ver.strdigits(),".jar" ) );
				if (r == -1 and errno != EEXIST) 
					throw xif::sys_error("failed to create symlink to minecraft_server.jar");
			}
			else if (s->s_serv_type == minecraft::serv_type::SPIGOT) jar_prefix = "mc_spigot_";
			else if (s->s_serv_type == minecraft::serv_type::BUNGEECORD) jar_prefix = "mc_bungeecord_";
			else  
				throw xif::sys_error("Minecraft .JAR type", "invalid value");
				// Get jar if needed and link in server directory
			jar_path = _s( MINECRAFT_JAR_DIR,'/',(jar_name=_s(jar_prefix,s->s_mc_ver.str(),".jar")) );
			r = ::access(jar_path.c_str(), R_OK);
			if (r == -1) {
				__log__(log_lvl::LOG, "FILES", logstream << "Getting jar " << jar_name << "...");
				minecraft::transferAndExtract(cli, minecraft::transferWhat::JAR, jar_name, MINECRAFT_JAR_DIR);
			}
			if (s->s_serv_type == minecraft::serv_type::FORGE or s->s_serv_type == minecraft::serv_type::CAULDRON) {
				std::string orig_jar_path = jar_path;
				r = ::link( orig_jar_path.c_str(), (jar_path=_S( working_dir,'/',jar_prefix,".jar" )).c_str() );
				if (r == -1 and errno != EEXIST) 
					throw xif::sys_error("failed to create link to forge|cauldron jar");
			}
		}
		s->s_jar_path = jar_path;
		
			// Changing directory owner and reset effective uid
		ioslaves::api::euid_switch(0,0);
		__ldebug__(NULL, MCLOGSCLI(s) << "Correcting permissions...");
		ioslaves::chown_recurse(working_dir.c_str(), minecraft::java_user_id, minecraft::java_group_id);
		ioslaves::api::euid_switch(-1,-1);
		
			// End of file requests, we can now start server
		__log__(log_lvl::IMPORTANT, NULL, MCLOGSCLI(s) << "All files are loaded, starting can start !");
		cli.o_char((char)ioslaves::answer_code::OK);
		
			// Early communication pipe
		fd_t early_pipes[2] = {INVALID_HANDLE, INVALID_HANDLE};
		r = ::pipe(early_pipes);
		if (r == -1)
			throw xif::sys_error("failed to create pipe for early server thread comm");
		s->s_early_pipe = early_pipes[1];
		__ldebug__("START", MCLOGCLI(servid) << "Set early pipe to [" << early_pipes[0] << "]<-" << early_pipes[1]);
		fd_t early_pipe_r = early_pipes[0];
		struct _autoclose_early_pipes { 
			minecraft::serv* s; fd_t r; ~_autoclose_early_pipes () {
				::close(r); ::close(s->s_early_pipe);
				__ldebug__("START", MCLOGSCLI(s) << "Close and invalidate early pipe " << r << "/" << s->s_early_pipe);
				s->s_early_pipe = INVALID_HANDLE;
			}
		} __autoclose_early_pipes({s,early_pipe_r});
		char _stat;
		auto _read_pipe_state_ = [&] (ushort tm_sec) {
			_stat = '_';
		_redo:
			timeval tm = {tm_sec,0};
			fd_set s; FD_ZERO(&s); FD_SET(early_pipe_r, &s);
			r = ::select(early_pipe_r+1, &s, NULL, NULL, &tm);
			if (r == -1 and errno == EINTR) goto _redo;
			if (r == 1)
				::read(early_pipe_r, &_stat, 1);
		};
		#define ReadEarlyStateIfNot(_excepted_char_, tm_sec) _read_pipe_state_(tm_sec); if (_excepted_char_ != _stat) 
		
		try {
		try {
		
				// Launch thraed
			r = ::pthread_create(&s->s_thread, NULL, minecraft::serv_thread, s);
			if (r != 0)
				throw xif::sys_error("failed to create server thread with pthread_create()", r);
			__autodelete_serv.s = NULL; // The thread is now the owner of structure `s`

				// Wait thread steps
			cli.o_char((char)ioslaves::answer_code::OK);
			ReadEarlyStateIfNot('y',1) {
				throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "START", MCLOGCLI(servid) << "Start failed before java start");
			}
			__ldebug__("START", MCLOGSCLI(s) << "Java will start...");
			ReadEarlyStateIfNot('j',1) {
				throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "START", MCLOGCLI(servid) << "Java start failed !");
			}
			time_t line_ack_timeout = 10;
			switch (s->s_serv_type) {
				case serv_type::BUKKIT: case serv_type::SPIGOT: case serv_type::BUNGEECORD: line_ack_timeout = 20; break;
				case serv_type::CAULDRON: case serv_type::FORGE: line_ack_timeout = 40; break;
				case serv_type::VANILLA: if (s->s_mc_ver <= ioslaves::version(1,7,10)) line_ack_timeout = 15; else line_ack_timeout = 20; break;
				case serv_type::CUSTOM: line_ack_timeout = 25; break;
			}
			ReadEarlyStateIfNot('l',line_ack_timeout) {
				throw ioslaves::req_err(ioslaves::answer_code::EXTERNAL_ERROR, "START", MCLOGCLI(servid) << "Didn't received ack of first line");
			}
			__log__(log_lvl::LOG, "START", "Java process is alive !");
			cli.o_char((char)ioslaves::answer_code::OK);
			if (early_console) {
				__log__(log_lvl::LOG, "START", "Quit thread monitoring in favor of early LiveConsole");
				return;
			}
			do {
				_read_pipe_state_(40);
			} while (_stat == 'l');
			if (_stat != 'd') {
				throw ioslaves::req_err(ioslaves::answer_code::EXTERNAL_ERROR, "START", MCLOGCLI(servid) << "Didn't received ack of \"Done\"");
			}
			__log__(log_lvl::DONE, "START", MCLOGCLI(servid) << "Minecraft wrote \"Done !\"");
			
				// Done !
			if (start_temp_perm)
				s->s_is_perm_map = true;
			cli.o_char((char)ioslaves::answer_code::OK);
			return;
		}
		catch (const socketxx::error& e) {
			__log__(log_lvl::ERROR, "START", MCLOGCLI(servid) << "Non-fatal network error : " << e.what());
			return;
		}
		} catch (...) {
			if (s->s_java_pid != -1) {
				__log__(log_lvl::NOTICE, "START", MCLOGCLI(servid) << "Killing java pid " << s->s_java_pid);
				asroot_block();
				::kill(s->s_java_pid, SIGKILL); // Killing java is a sufficient sign to the thread, it should NOT be canceled
				minecraft::deleteLckFiles(working_dir);
			}
			throw;
		}
		
	} catch (const ioslaves::req_err& re) {
		cli.o_char((char)re.answ_code);
	} catch (const xif::sys_error& se) {
		__log__(log_lvl::ERROR, "START", MCLOGCLI(servid) << "Internal sys error : " << se.what());
		cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR);
	} catch (const std::runtime_error& re) {
		__log__(log_lvl::ERROR, "START", MCLOGCLI(servid) << "Exception : " << re.what());
		cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR);
	} catch (const socketxx::error& e) {
		__log__(log_lvl::ERROR, "START", MCLOGCLI(servid) << "Network error : " << e.what());
	}
}
		
	/// Server thread

// Interpret java outputs. Interpret requests can be queued by commands, waiting for a specific pattern in log
struct interpret_request {
	socketxx::io::simple_socket<socketxx::base_socket>* sock;
	void* data;
	std::vector<std::string> patterns_beg;
	time_t req_end;
	std::function<bool (decltype(sock), std::string msg, interpret_request*)> f_callback; // ret true = end of request, autodel ctx data sock
	std::function<void (decltype(sock), interpret_request*)> f_expire;
};
std::string MC_log_interpret (std::string line, minecraft::serv*, minecraft::serv_stopped*, std::list<interpret_request*>&);

void MC_write_command (minecraft::serv* s, pipe_proc_t java_pipes, std::string cmd);
#define WriteEarlyState(_char_) _stat = _char_; ::write(s->s_early_pipe, &_stat, 1);

void* minecraft::serv_thread (void* arg) {
	char _stat;
	int r;
	logl_t l;
	minecraft::serv* s = (minecraft::serv*)arg;
	
	bool mutex_locked = false;
	RAII_AT_END_N(mutex, {
		if (mutex_locked) {
			::pthread_mutex_unlock(&minecraft::servs_mutex); MUTEX_UNLOCKED;
		}
	});
	
		// Prepare stop structure
	minecraft::serv_stopped stopInfo;
	stopInfo.serv = s->s_servid;
	stopInfo.map_to_save = "";
	stopInfo.why = minecraft::whyStopped::NOT_STARTED;
	stopInfo.gracefully = false;
	stopInfo.doneDone = false;
	
		// First error catching level `starting java`
	try {
		fd_set select_set;
		fd_t select_max = 0;
		FD_ZERO(&select_set);
		
			// Block signals
		sigset_t sigs_main_blocked;
		sigemptyset(&sigs_main_blocked);
		for (size_t si = 0; sigs_to_block[si] != (int)NULL; ++si)
			sigaddset(&sigs_main_blocked, sigs_to_block[si]);
		::pthread_sigmask(SIG_BLOCK, &sigs_main_blocked, NULL);
		
			// Run thread as mcjava
		ioslaves::api::euid_switch(minecraft::java_user_id, minecraft::java_group_id);
		
			// Open server socket
		fd_t s_sockets_comm[2] = {INVALID_HANDLE, INVALID_HANDLE};
		r = ::socketpair(AF_UNIX, SOCK_STREAM, 0, s_sockets_comm);
		if (r == -1)
			throw xif::sys_error("can't create socket pair for server thread communication");
		s->s_sock_comm = s_sockets_comm[1];
		fd_t comm_socket = s_sockets_comm[0];
		__ldebug__(THLOGSCLI(s), logstream << "Set internal comm socket to [" << s_sockets_comm[0] << "]<->" << s_sockets_comm[1]);
		FD_SET(comm_socket, &select_set);
		select_max = comm_socket;
		
			// Communication pipes are now etablished
		WriteEarlyState('y');
		
			// Contructing arguments list
		std::vector<std::string> args = {
/*#ifdef __x86_64__
			"-d64",
#endif*/
			"-XX:+UseParallelGC",
			"-XX:MaxPermSize=200M",
			_S("-Xmx",::ixtoa(s->s_megs_ram),"M"), _S("-Xms",::ixtoa(s->s_megs_ram),"M"),
			"-jar", s->s_jar_path,
			"--world", s->s_map,
		};
		if (s->s_serv_type == minecraft::serv_type::VANILLA or s->s_serv_type == minecraft::serv_type::CUSTOM) 
			args.push_back("--nogui");
		
		std::string _args = "java ";
		for (std::string _arg : args) _args += _arg + ' ';
		__ldebug__(THLOGSCLI(s), logstream << "Launching java with `" << _args << "`");
		
			// Forking process and executing java
		pipe_proc_t java_pipes;
		{ asroot_block();
			std::tie(s->s_java_pid, java_pipes)
				= ioslaves::fork_exec("java", args, true, s->s_wdir.c_str(), true, minecraft::java_user_id, minecraft::java_group_id, false);
		}
		
			// Java StdIO handling
		FD_SET(java_pipes.out, &select_set);
		FD_SET(java_pipes.err, &select_set);
		select_max = std::max({java_pipes.out, java_pipes.err, select_max});
		RAII_AT_END_N(pipes, {
			::close(java_pipes.err);
			::close(java_pipes.out);
			::close(java_pipes.in);
		});
		
			// Java is now launched
		WriteEarlyState('j');
		s->s_start_iosl_time = ::iosl_time();
		
			// Registering as opened server
		{ pthread_mutex_handle_lock(minecraft::servs_mutex);
			minecraft::servs[s->s_servid] = s;
		}
		
		{	// Add SRV entry on DNS
			ioslaves::api::euid_switch(-1,-1);
			RAII_AT_END_L( ioslaves::api::euid_switch(minecraft::java_user_id, minecraft::java_group_id) );
			ioslaves::answer_code new_srv_answ = (*ioslaves::api::dns_srv_create)("minecraft", XIFNET_MC_DOM, s->s_servid, true, s->s_port, true);
			if (new_srv_answ != ioslaves::answer_code::OK) 
				__log__(log_lvl::ERROR, "SERV", MCLOGSCLI(s) << "Failed to create SRV entry on DNS for domain " << s->s_servid << '.' << XIFNET_MC_DOM << " : " << ioslaves::getAnswerCodeDescription(new_srv_answ));
			else 
				__log__(log_lvl::LOG, "SERV", MCLOGSCLI(s) << "Created SRV entry on DNS for domain " << s->s_servid << '.' << XIFNET_MC_DOM << ':' << s->s_port);
		}
		
		{ // Open additional ports (should be unique across the network)
			if (s->s_oth_ports.size() != 0) 
				__log__(log_lvl::LOG, "SERV", MCLOGSCLI(s) << "Opening additional ports...");
			for (in_port_t port : s->s_oth_ports) {
				ioslaves::answer_code o = (*ioslaves::api::open_port)(port, true, port, 1, "additional port for mc serv");
				if (o != ioslaves::answer_code::OK) 
					__log__(log_lvl::ERROR, "SERV", MCLOGSCLI(s) << "Failed to open additional port " << port << " : " << ioslaves::getAnswerCodeDescription(o));
			}
		}
		
			// Live console
		struct log_line { time_t time; std::string msg; };
		std::vector<log_line> log_hist;
		std::string current_line;
		std::list<socketxx::io::simple_socket<socketxx::base_netsock>*> live_consoles;
		std::list<interpret_request*> interpret_requests;
		
			// Autoclose & player listing
		#define MINECRAFT_LIST_PATTERNS_BEG {"There are ", "Il y a "}
		time_t first_0 = 0;
		auto parse_list_players = [&s] (std::string msg, interpret_request* req) -> uint16_t {
			if (s->s_serv_type == minecraft::serv_type::VANILLA) {
				msg = msg.substr(req->patterns_beg.front().length(), std::string::npos);
				msg = msg.substr(0, msg.find_first_of('/'));
			} else {
				std::string tmp;
				for (size_t i = 0; i < msg.length(); i++) {
					if (::isdigit(msg[i])) 
						tmp += msg[i];
					else if (not tmp.empty()) 
						break;
				}
				msg = tmp;
			}
			return ::atoix<uint16_t>(msg, IX_DEC);
		};
		
			// Second error catching level `java started`
		__retry:
		try {
			bool loop = true;
			while (loop) {
				
				fd_set sel_set = select_set;
				timeval select_timeout = {1,0};
				r = ::select(select_max+1, &sel_set, NULL, NULL, &select_timeout);
				
				if (r == SOCKET_ERROR) {
					throw xif::sys_error("error during select() in minecraft service server thread");
				}
					// Timeout
				else if (r == 0) {
					if (::time(NULL)%20 == 0 and stopInfo.doneDone and s->s_is_perm_map) {
						lastsaveTimeFile(_S( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map ), true);
					}
					
						// Autoclose server
					if (s->s_delay_noplayers != 0 and ::time(NULL)%160 == 0) {
						MC_write_command(s, java_pipes, "list");
						interpret_request* int_req = new interpret_request;
						int_req->data = int_req->sock = NULL;
						int_req->patterns_beg = MINECRAFT_LIST_PATTERNS_BEG;
						int_req->f_callback = [&first_0, &s, &parse_list_players, &stopInfo, &java_pipes] (void*, std::string msg, interpret_request* req) -> bool {
							try {
								uint16_t n_players = parse_list_players(msg, req);
								if (n_players == 0) {
									if (first_0 == 0) {
										first_0 = ::iosl_time();
									} else {
										if (::iosl_time()- first_0 > s->s_delay_noplayers) {
											__log__(log_lvl::IMPORTANT, THLOGSCLI(s), logstream << "There were no players for " << (::iosl_time()-first_0) << "s. Closing server...");
											stopInfo.why = minecraft::whyStopped::DESIRED_INTERNAL;
											MC_write_command(s, java_pipes, "stop");
										}
									}
								} else 
									first_0 = 0;
							} catch (const std::exception& e) { first_0 = 0; }
							return true;
						};
						int_req->req_end = ::time(NULL)+1;
						int_req->f_expire = [&first_0] (void*, interpret_request* req) { first_0 = 0; };
						interpret_requests.insert(interpret_requests.end(), int_req);
					}
				}
				else if (r >= 1) {
					
						// Check for java output
					if (FD_ISSET(java_pipes.out, &sel_set) or FD_ISSET(java_pipes.err, &sel_set)) {
						errno = 0;
						char lbuf[1024];
						fd_t out = FD_ISSET(java_pipes.err, &sel_set) ? java_pipes.err : java_pipes.out;
						ssize_t rs = ::read(out, lbuf, sizeof(lbuf));
						if (rs == 0) {
							__log__(log_lvl::NOTICE, THLOGSCLI(s), "Java pipe closed. Waiting for sigchild...");
							#warning TO DO : Add timeout
							FD_CLR(java_pipes.out, &select_set);
							FD_CLR(java_pipes.err, &select_set);
							::close(java_pipes.in);
							java_pipes.in = INVALID_HANDLE;
							goto __retry;
						}
						if (rs == -1)
							throw xif::sys_error("read from java stdout failed");
						
						current_line.insert(current_line.length(), lbuf, (size_t)rs);
						for (size_t i = 0; i < current_line.length(); i++) {
							if (current_line[i] == '\n') {
								std::string line = current_line.substr(0,i);
								current_line.erase(0,i+1);
								i = 0;
								
								MC_log_interpret(line, s, &stopInfo, interpret_requests);
								timeval utc_time; ::gettimeofday(&utc_time, NULL);
								log_hist.push_back( log_line({utc_time.tv_sec, line}) );
								
								for (auto it = live_consoles.begin(); it != live_consoles.end();) {
									try {
										(*it)->o_int<int64_t>(utc_time.tv_sec);
										(*it)->o_str(line); 
									} catch (const socketxx::error& e) { 
										__ldebug__(THLOGSCLI(s), "Live console client hanged up");
										FD_CLR((*it)->socketxx::base_fd::get_fd(), &select_set);
										delete *it;
										auto p_it = it++; live_consoles.erase(p_it);
										continue;
									}
									it++;
								}
							}
						}
					}
					
						// Check for internal communication pipe input
					if (FD_ISSET(comm_socket, &sel_set)) {
						socketxx::io::simple_socket<socketxx::base_fd> comms(socketxx::base_socket(comm_socket, SOCKETXX_MANUAL_FD));
						minecraft::internal_serv_op_code opp = (minecraft::internal_serv_op_code)comms.i_char();
						__ldebug__(THLOGSCLI(s), logstream << "Internal request on socket [" << comm_socket << "]<->" << s->s_sock_comm);
						switch (opp) {
								
							case minecraft::internal_serv_op_code::CHAT_WITH_CLIENT: {
								socketxx::base_netsock cli_sock = socketxx::base_netsock(socketxx::base_socket( comms.i_sock() ));
								socketxx::io::simple_socket<socketxx::base_netsock> cli = cli_sock;
								try {
									cli.o_char((char)ioslaves::answer_code::OK);
									minecraft::serv_op_code op = (minecraft::serv_op_code)cli.i_char();
									switch (op) {
										case minecraft::serv_op_code::LIVE_CONSOLE: {
											bool send_all_log = cli.i_bool();
											cli.o_char((char)ioslaves::answer_code::OK);
											if (send_all_log) {
												for (const log_line& line : log_hist) {
													cli.o_int<int64_t>(line.time);
													cli.o_str(line.msg);
												}
											}
											live_consoles.push_back( new socketxx::io::simple_socket<socketxx::base_netsock>(cli) );
											fd_t cnle_fd = cli.socketxx::base_fd::get_fd();
											FD_SET(cnle_fd, &select_set);
											if (cnle_fd > select_max) select_max = cnle_fd;
											__log__(log_lvl::LOG, THLOGSCLI(s), "New live console client");
										} break;	
										case minecraft::serv_op_code::EXEC_MC_COMMAND: {
											std::string cmd = cli.i_str();
											__log__(log_lvl::NOTICE, THLOGSCLI(s), logstream << "Master wants execute command `" << cmd << "`");
											MC_write_command(s, java_pipes, cmd);
											cli.o_char((char)ioslaves::answer_code::OK);
										} break;
										default: throw ioslaves::req_err(ioslaves::answer_code::OP_NOT_DEF, THLOGSCLI(s), MCLOGSCLI(s) << "Server external request : invalid '" << (char)op << "' operation");
									}
								} catch (const ioslaves::req_err& re) {
									try {
										cli.o_char((char)re.answ_code);
									} catch (...) {}
								} catch (const socketxx::error& e) {
									__log__(log_lvl::OOPS, THLOGSCLI(s), logstream << "Network error with external client : " << e.what());
								}
							} break;
							
							case minecraft::internal_serv_op_code::GET_PLAYER_LIST: {
								MC_write_command(s, java_pipes, "list");
								interpret_request* int_req = new interpret_request;
								int_req->data = NULL;
								int_req->patterns_beg = MINECRAFT_LIST_PATTERNS_BEG;
								int_req->sock = new socketxx::io::simple_socket<socketxx::base_socket>( comms );
								int_req->f_callback = [&parse_list_players,&first_0,s] (decltype(int_req->sock) sock, std::string msg, interpret_request* req) -> bool {
									try {
										uint16_t n_players = parse_list_players(msg, req);
										sock->o_char((char)ioslaves::answer_code::OK);
										sock->o_int<int16_t>(n_players);
										__ldebug__(THLOGSCLI(s), logstream << "Reported " << n_players << " players.");
										sock->o_int<uint32_t>((uint32_t)first_0);
									} catch (const std::exception& e) {
										try {
											sock->o_char((char)ioslaves::answer_code::ERROR);
										} catch (...) {}
									}
									return true;
								};
								int_req->req_end = ::time(NULL)+1;
								int_req->f_expire = [] (decltype(int_req->sock) s, interpret_request* req) {
									try {
										s->o_char((char)ioslaves::answer_code::ERROR);
									} catch (...) {}
								};
								interpret_requests.insert(interpret_requests.end(), int_req);
							} break;
								
							case minecraft::internal_serv_op_code::STOP_SERVER_CLI: {
								__log__(log_lvl::MAJOR, THLOGSCLI(s), "Stopping server...");
								MC_write_command(s, java_pipes, "say [AUTO] Fermeture depuis le panel");
								::sleep(2);
								stopInfo.why = minecraft::whyStopped::DESIRED_MASTER;
								MC_write_command(s, java_pipes, "stop");
								WriteEarlyState('s');
							} break;
							
							case minecraft::internal_serv_op_code::STOP_SERVER_NOW: {
								__log__(log_lvl::WARNING, THLOGSCLI(s), "Stopping server from ioslaves : save will be not reported");
								MC_write_command(s, java_pipes, "say [AUTO] Le serveur doit se fermer immediatement (reboot ou shutdown machine)");
								::sleep(2);
								stopInfo.why = minecraft::whyStopped::DESIRED_INTERNAL;
								MC_write_command(s, java_pipes, "stop");
							} break;
								
							case minecraft::internal_serv_op_code::KILL_JAVA: {
								__log__(log_lvl::WARNING, THLOGSCLI(s), "Killing java !");
								stopInfo.gracefully = false;
								stopInfo.why = minecraft::whyStopped::KILLED;
								{ asroot_block();
									::kill(s->s_java_pid, SIGKILL);
								}
							} break;
							
							case minecraft::internal_serv_op_code::GOT_SIGNAL: {
								int pid_status = comms.i_int<int>();
								__log__(log_lvl::NOTICE, THLOGSCLI(s), logstream << "Got SIGCHLD : java exited with retcode " << WEXITSTATUS(pid_status));
								if (s->s_early_pipe != INVALID_HANDLE) WriteEarlyState('g');
								stopInfo.gracefully = (WEXITSTATUS(pid_status) == 0);
								if (stopInfo.why == (minecraft::whyStopped)0) stopInfo.why = minecraft::whyStopped::ITSELF;
								loop = false;
							} break;
							
							default: __log__(log_lvl::ERROR, THLOGSCLI(s), logstream << "Invalid internal op '" << (char)opp << "'"); break;
						}
					}
					
						// Check for LiveConsole clients input
					for (auto it = live_consoles.begin(); it != live_consoles.end();) {
						if (FD_ISSET((*it)->socketxx::base_fd::get_fd(), &sel_set)) {
							try {
								std::string cmd = (*it)->i_str();
								__log__(log_lvl::_DEBUG, THLOGSCLI(s), logstream << "Command from live console : '" << cmd << "'");
								MC_write_command(s, java_pipes, cmd);
								(*it)->o_char((char)ioslaves::answer_code::OK);
							} catch (const socketxx::error& e) { 
								__ldebug__(THLOGSCLI(s), logstream << "Live console client hanged up");
								FD_CLR((*it)->socketxx::base_fd::get_fd(), &select_set);
								delete *it;
								auto p_it = it++; live_consoles.erase(p_it);
								continue;
							}
						}
						++it;
					}
					
				}
				
				// Interpret request timeout
				for (auto it = interpret_requests.begin(); it != interpret_requests.end();) {
					interpret_request* int_req = *it;
					if (::time(NULL) >= int_req->req_end) {
						RAII_AT_END({
							if (int_req->sock != NULL)
								delete int_req->sock;
							delete int_req;
						});
						if (int_req->f_expire != NULL)
							(int_req->f_expire)(int_req->sock, int_req);
						auto p_it = it++; interpret_requests.erase(p_it);
					} else 
						++it;
				}
				
				continue;
			}
		} catch (const xif::sys_error& sys_err) {
			__log__(log_lvl::ERROR, THLOGSCLI(s), logstream << "Error in `java launched` state : " << sys_err.what());
		} catch (const socketxx::error& sock_err) {
			__log__(log_lvl::ERROR, THLOGSCLI(s), logstream << "Network error : " << sock_err.what());
			goto __retry;
		}
		
		bool fixedworld = not ioslaves::infofile_get(_s( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map,"/fixed_map" ), true).empty();

			// Stopping : we don't want to be contacted
		MUTEX_PRELOCK; ::pthread_mutex_lock(&minecraft::servs_mutex); MUTEX_POSTLOCK;
		mutex_locked = true;
		::close(s_sockets_comm[1]);
		::close(s_sockets_comm[0]);
		
			// Bye LiveConsole clients...
		if (live_consoles.size() != 0) {
			__ldebug__(THLOGSCLI(s), logstream << "Ejecting live console clients");
			for (auto it = live_consoles.begin(); it != live_consoles.end(); it++) {
				try {
					(*it)->o_int<int64_t>(-1);
				} catch (...) {}
				delete *it;
			}
		}
		for (auto it = interpret_requests.begin(); it != interpret_requests.end(); it++) {
			interpret_request* int_req = *it;
			RAII_AT_END({
				if (int_req->sock != NULL)
					delete int_req->sock;
				delete int_req;
			});
			if (int_req->f_expire != NULL) (int_req->f_expire)(int_req->sock, int_req);
		}
		
			// Delete FTP sessions
		if (not fixedworld) 
			minecraft::ftp_del_sess_for_serv(s->s_servid, 30);
		
			// Last-save-time
		if (stopInfo.doneDone and s->s_is_perm_map) {
			if (not fixedworld)
				stopInfo.map_to_save = s->s_map;
			lastsaveTimeFile(_S( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map ), true);
		}
		if (stopInfo.doneDone) {
			time_t run_time = (::iosl_time() - s->s_start_iosl_time) / 60;
			if (run_time < 60)
				__log__(log_lvl::LOG, THLOGSCLI(s), logstream << "Run time : " << run_time/60 << "h " << run_time%60 << 'm');
			else
				__log__(log_lvl::LOG, THLOGSCLI(s), logstream << "Run time : " << run_time << 'm');
		}

			// Normally the server is already closed. Else, close server ungracefully but softly with SIGHUP.
		{ asroot_block();
			r = ::kill(s->s_java_pid, SIGHUP);
		}
		if (r == -1) {
			if (errno == ESRCH) 
				__log__(log_lvl::_DEBUG, THLOGSCLI(s), logstream << "Java is already stopped", LOG_WAIT, &l);
			else throw xif::sys_error("kill java failed");
		} else {
			__log__(log_lvl::NOTICE, THLOGSCLI(s), logstream << "SIGHUP signal sent to java", LOG_WAIT, &l);
			stopInfo.gracefully = false;
		}
		int status;
		pid_t r_pid = ::waitpid(s->s_java_pid, &status, WUNTRACED);
		if (r_pid == s->s_java_pid) {
			log_lvl r_pid_lvl = (WEXITSTATUS(status) == 0) ? log_lvl::DONE : log_lvl::WARNING;
			__log__(r_pid_lvl, NULL, logstream << "(ret code " << WEXITSTATUS(status) << ")", LOG_ADD, &l);
		}
			// Delete remaining .lck files
		minecraft::deleteLckFiles(_S( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map ));
		
		{ // Delete SRV entry on DNS
			ioslaves::api::euid_switch(-1,-1);
			RAII_AT_END_L( ioslaves::api::euid_switch(minecraft::java_user_id, minecraft::java_group_id) );
			__ldebug__(THLOGSCLI(s), logstream << "Closing SRV entry...");
			(*ioslaves::api::dns_srv_del)("minecraft", XIFNET_MC_DOM, s->s_servid, true);
		}
		
			// Close additional ports
		if (s->s_oth_ports.size() != 0) 
			__log__(log_lvl::LOG, THLOGSCLI(s), logstream << "Closing additional ports...");
		for (in_port_t port : s->s_oth_ports) 
			(*ioslaves::api::close_port)(port, 1, true);
		
	} catch (const xif::sys_error& sys_err) {
		__log__(log_lvl::ERROR, THLOGSCLI(s), logstream << "Error in `starting java` state : " << sys_err.what());
	} catch (const std::runtime_error) {
		__log__(log_lvl::ERROR, THLOGSCLI(s), logstream << "Fatal error");
	}
	
		// If start method is still waiting us
	if (s->s_early_pipe != INVALID_HANDLE) { WriteEarlyState('E'); }
	
		// Delete server entry and add it in stopped servers list
	if (not mutex_locked) {
		MUTEX_PRELOCK; ::pthread_mutex_lock(&minecraft::servs_mutex); MUTEX_POSTLOCK;
		mutex_locked = true;
	}
	try { 
		minecraft::servs.erase(s->s_servid);
	} catch (...) {}
	if (stopInfo.why != minecraft::whyStopped::DESIRED_MASTER and stopInfo.why != minecraft::whyStopped::NOT_STARTED) {
		minecraft::servs_stopped.push_back(stopInfo);
		__log__(log_lvl::NOTICE, THLOGSCLI(s), logstream << "Stop report saved");
	}

		// Close port
	(*ioslaves::api::close_port)(s->s_port, 1, true);
	
		// Delete big-files and jars symlinks
	std::vector<minecraft::_BigFiles_entry> bigfiles = minecraft::getBigFilesIndex(_S( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map ));
	for (minecraft::_BigFiles_entry entry : bigfiles) {
		r = ::unlink(entry.final_path.c_str());
	}
	if (s->s_serv_type == minecraft::serv_type::FORGE or s->s_serv_type == minecraft::serv_type::CAULDRON) {
		r = ::unlink(_s( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map,"/minecraft_server.",s->s_mc_ver.strdigits(),".jar" ));
		r = ::unlink(_s( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map,"/libraries" ));
		r = ::unlink(s->s_jar_path.c_str());
		if (s->s_serv_type == minecraft::serv_type::CAULDRON) 
			r = ::unlink(_s( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map,"/cauldronbukkit-",s->s_mc_ver.str(),".jar" ));
	}
	
		// Delete map folder if temporary
	if (not s->s_is_perm_map) 
		minecraft::deleteMapFolder(s);
	
		// Well... bye !
	if (stopInfo.why != minecraft::whyStopped::DESIRED_MASTER) {
		__log__(log_lvl::IMPORTANT, THLOGSCLI(s), logstream << "-= EXIT =- no stop method");
		delete s;
		return NULL;
	} else {
		__log__(log_lvl::IMPORTANT, THLOGSCLI(s), logstream << "-= EXIT =- relaying to main stop method");
		return s;
	}
}

	// Write command to Minecraft server
void MC_write_command (minecraft::serv* s, pipe_proc_t java_pipes, std::string cmd) {
	if (java_pipes.in == INVALID_HANDLE) return;
	__ldebug__(THLOGSCLI(s), logstream << "> " << cmd);
	errno = 0;
	ssize_t rs;
	rs = ::write(java_pipes.in, _s(cmd,'\n'), cmd.length()+1);
	if (rs != (ssize_t)cmd.length()+1) throw xif::sys_error(_S("failed to write command to java"));
}
	// Interpret log line
inline void _str_delLastSpace (std::string& str) { if (not str.empty() and str[str.length()-1] == ' ') str.resize(str.length()-1); }
std::string MC_log_interpret (const std::string line, minecraft::serv* s, minecraft::serv_stopped* stopInfo, std::list<interpret_request*>& int_req_list) {
	if (s->s_early_pipe != INVALID_HANDLE) {
		char _stat; WriteEarlyState('l');
	}
	bool hour_brackets = false;
	bool hour_and_part = false;
	if (s->s_serv_type == minecraft::serv_type::VANILLA) {
		if (s->s_mc_ver >= ioslaves::version(1,7,0)) hour_brackets = true;
	} else if (s->s_serv_type == minecraft::serv_type::BUKKIT or s->s_serv_type == minecraft::serv_type::CAULDRON) {
		if (s->s_mc_ver >= ioslaves::version(1,7,0)) { hour_brackets = true; hour_and_part = true; }
	} else if (s->s_serv_type == minecraft::serv_type::FORGE) {
		hour_brackets = true;
	}
	enum { DATE, PART, MSG } ctx = DATE;
	std::string m_date;
	std::string m_part;
	std::string m_msg;
	for (size_t i = (hour_brackets?1:0); i < line.length(); i++) {
		if (ctx == DATE) {
			if (not hour_and_part) {
				if (hour_brackets) { if (line[i] == ']') { ctx = PART; i++; continue; } }
				else { if (line[i] == '[') { _str_delLastSpace(m_date); ctx = PART; continue; } }
			} else 
				if (line[i] == ' ') { if (not m_date.empty()) m_date.erase(m_date.begin()); ctx = PART; continue; };
			m_date += line[i];
		} else if (ctx == PART) {
			if (line[i] == ']') { ctx = MSG; continue; }
			if (line[i] != '[')
				m_part += line[i];
		} else if (ctx == MSG) {
			if (line[i] == ':' or line[i] == ' ') continue;
			m_msg = line.substr(i, std::string::npos);
			break;
		}
	}
	if (ctx != MSG) { 
		__log__(log_lvl::_DEBUG, THLOGSCLI(s), logstream << "-- " << line, (stopInfo->doneDone?LOG_NO_HISTORY:0));
		return line;
	} else {
		__log__(log_lvl::_DEBUG, THLOGSCLI(s), logstream << "-- [" << m_part << "] " << m_msg, (stopInfo->doneDone?LOG_NO_HISTORY:0));
		if (ctx != MSG) return m_msg;
	}
	for (auto it = int_req_list.begin(); it != int_req_list.end(); it++) {
		interpret_request* int_req = *it;
		for (const std::string patten : int_req->patterns_beg) {
			if (patten.length() == 0 or m_msg.std::string::find(patten) == 0) {
				int_req->patterns_beg = { patten };
				bool r = (int_req->f_callback)(int_req->sock, m_msg, int_req);
				if (r) {
					if (int_req->sock != NULL)
						delete int_req->sock;
					delete int_req;
					auto p_it = it++; int_req_list.erase(p_it);
				} else 
					it++;
				break;
			}
		}
	}
	if (m_msg.std::string::find("Done (") == 0) {
		char _stat; WriteEarlyState('d');
		stopInfo->doneDone = true;
		stopInfo->why = (minecraft::whyStopped)0;
	} 
	else if (m_msg.std::string::find("Stopping server") == 0) {
		__log__(log_lvl::NOTICE, THLOGSCLI(s), logstream << "Server said it is stopping !");
		if (s->s_early_pipe != INVALID_HANDLE) { char _stat; WriteEarlyState('S'); }
		stopInfo->gracefully = true;
		if (stopInfo->why == (minecraft::whyStopped)0) stopInfo->why = minecraft::whyStopped::ITSELF;
	}
	return m_msg;
}

	/// Stop
void minecraft::stopServer (socketxx::io::simple_socket<socketxx::base_socket> cli, minecraft::serv* s, pthread_mutex_handle& _mutex_handle_) {
	int r;
	std::string servid = s->s_servid;
	
	try {
		
			// Late communication pipe
		fd_t late_pipes[2] = {INVALID_HANDLE, INVALID_HANDLE};
		r = ::pipe(late_pipes);
		if (r == -1)
			throw xif::sys_error("failed to create pipe for early server thread comm");
		s->s_early_pipe = late_pipes[1];
		__ldebug__("STOP", MCLOGCLI(servid) << "Set late pipe to [" << late_pipes[0] << "]<-" << late_pipes[1]);
		struct _autoclose_late_pipes { 
			fd_t w,r; ~_autoclose_late_pipes () {
				::close(r); ::close(w);
				__ldebug__("STOP", logstream << "Close late pipe " << r << "/" << w);
			}
		} __autoclose_late_pipes({late_pipes[0],late_pipes[1]});
		char _stat;
		auto _read_pipe_state_ = [&] (ushort tm_sec) {
			_stat = '_';
		_redo:
			timeval tm = {tm_sec,0};
			fd_set s; FD_ZERO(&s); FD_SET(late_pipes[0], &s);
			int r = ::select(late_pipes[0]+1, &s, NULL, NULL, &tm);
			if (r == -1 and errno == EINTR) goto _redo;
			if (r == 1)
				::read(late_pipes[0], &_stat, 1);
		};
		
			// Sending stop command and release mutex
		socketxx::io::simple_socket<socketxx::base_fd> s_comm(socketxx::base_fd(s->s_sock_comm, SOCKETXX_MANUAL_FD));
		s_comm.o_char((char)minecraft::internal_serv_op_code::STOP_SERVER_CLI);
		_mutex_handle_.soon_unlock();
		
			// Waiting for stop
		ReadEarlyStateIfNot('s',5) {
			throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "STOP", MCLOGCLI(servid) << "Didn't received stop command ack");
		}
		cli.o_char((char)ioslaves::answer_code::OK);
		time_t timeout = ::time(NULL)+35;
		do {
			errno = 0;
			_read_pipe_state_(6);
			if (_stat == 'S') 
				timeout += 15;
			if (timeout < ::time(NULL)) 
				break;
		} while (_stat == 'S' or _stat == 'l');
		cli.o_char((char)ioslaves::answer_code::OK);
		if (_stat != 'g') {
			if (_stat == '_')
				throw ioslaves::req_err(ioslaves::answer_code::TIMEOUT, "STOP", MCLOGSCLI(s) << "Timeout : server didn't stop");
			else
				throw ioslaves::req_err(ioslaves::answer_code::ERROR, "STOP", MCLOGSCLI(s) << "Didn't received sigchild ack (" << _stat << ")");
		}
		ReadEarlyStateIfNot('E',6) {
			throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "STOP", MCLOGSCLI(s) << "Didn't received ack of thread secondary cleanup");
		}
		
			// Wait thread cleanup/exit and get back the thread structure
		minecraft::serv* s_th = NULL;
		::pthread_join(s->s_thread, (void**)&s_th);
		if (s_th == NULL or s_th != s) {
			throw ioslaves::req_err(ioslaves::answer_code::INTERNAL_ERROR, "STOP", MCLOGCLI(servid) << "Failed to retrieve server structure");
		}
		RAII_AT_END_N(del, { // Server structure will be finally deleted by us
			delete s;
		});
		__ldebug__("STOP", "Ok, thread is exited");
		cli.o_char((char)ioslaves::answer_code::OK);
		
		if (s->s_is_perm_map) {
			__log__(log_lvl::IMPORTANT, "STOP", MCLOGSCLI(s) << "Reporting server stop");
			cli.o_char((char)ioslaves::answer_code::WANT_REPORT);
			cli.o_str(s->s_servid);
			cli.o_char((char)minecraft::whyStopped::DESIRED_MASTER);
			cli.o_bool(true);
			cli.o_bool(false);
			bool fixedworld = not ioslaves::infofile_get(_s( MINECRAFT_SRV_DIR,"/mc_",s->s_servid,'/',s->s_map,"/fixed_map" ), true).empty();
			cli.o_str( fixedworld ? std::string() : s->s_map );
			bool accept = cli.i_bool();
			if (accept) {
				if (not fixedworld) {
					block_as_mcjava();
					minecraft::compressAndSend(cli, s->s_servid, s->s_map, true);
				}
			} else 
				__log__(log_lvl::WARNING, "STOP", MCLOGSCLI(s) << "Master refused stop report ! Scandal !");
		}
		
		cli.o_char((char)ioslaves::answer_code::OK);
		__log__(log_lvl::DONE, "STOP", MCLOGSCLI(s) << "Server successfully stopped");
		
	} catch (const ioslaves::req_err& re) {
		cli.o_char((char)re.answ_code);
	} catch (const xif::sys_error& se) {
		__log__(log_lvl::ERROR, "STOP", MCLOGSCLI(s) << "Internal sys error : " << se.what());
		cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR);
	}
}
