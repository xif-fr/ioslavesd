/**********************************************************\
 *               -== Xif Network project ==-
 *                   ioslaves API header
 *            Control interface for XifNet services
 * *********************************************************
 * Copyright © Félix Faisant 2013-2015. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

#ifndef _IOSLAVESD_API_H
#define _IOSLAVESD_API_H

namespace ioslaves { struct service; }

#include <pthread.h>
class pthread_mutex_handle {
	pthread_mutex_t* const _mutex;
public: pthread_mutex_handle (pthread_mutex_t* mutex) : _mutex(mutex) { ::pthread_mutex_lock(_mutex); }
	~pthread_mutex_handle () { ::pthread_mutex_trylock(_mutex); ::pthread_mutex_unlock(_mutex); }
};
#define pthread_mutex_handle_lock(mutex) pthread_mutex_handle _mutex_handle_ (&mutex)

// Signals to block in api service's threads
#include <signal.h>
extern int sigs_to_block[];
extern sig_atomic_t* signal_catch_sigchild_p;
#if defined(IOSLAVESD_API_MAIN_PROG_IMPL) || defined (IOSLAVESD_API_SERVICE_IMPL)
	int sigs_to_block[] = { SIGINT, SIGQUIT, SIGHUP, SIGTERM, SIGCHLD, (int)NULL };
	sig_atomic_t* signal_catch_sigchild_p;
#endif
// Block signals
inline void thread_block_signals () {
	sigset_t sigs_main_blocked;
	sigemptyset(&sigs_main_blocked);
	for (size_t si = 0; sigs_to_block[si] != (int)NULL; ++si)
		sigaddset(&sigs_main_blocked, sigs_to_block[si]);
	::pthread_sigmask(SIG_BLOCK, &sigs_main_blocked, NULL);	
}
// Call this when using system() - system() can't be used in other threads than main
struct _block_sigchild {
	_block_sigchild () { *signal_catch_sigchild_p = false; }
	~_block_sigchild () { *signal_catch_sigchild_p = true; }
};
#define sigchild_block() _block_sigchild _block_sigchild_handle

#define XIF_LOG_DEFAULT_LOGSTREAM
#include "log.h"
#include "common.hpp"
#include <xifutils/polyvar.hpp>

/// Common ioslavesd data and variables
namespace ioslaves { namespace api {
	
	struct common_vars_t {
		const xif::polyvar::map* system_stat;
		const time_t* shutdown_time;
	};
	
	extern common_vars_t* common_vars;

#ifdef IOSLAVESD_API_MAIN_PROG_IMPL
	extern common_vars_t api_vars;
	common_vars_t* common_vars = &api_vars;
#endif
	
	struct api_perm_t {
		bool by_default;
		std::map<std::string,std::string> props;
		bool operator[] (std::string idx) {
			     if (this->props[idx] == "true")  return true;
			else if (this->props[idx] == "false") return false;
			else                                  return by_default;
		}
	};
	
}}

/// Common callbacks definitions
namespace ioslaves { namespace api {
	
	typedef void (*report_log_f) (ioslaves::service*, xlog::log_lvl, const char*, std::string&, int, xlog::logl_t*); // Report a log line
	typedef ioslaves::answer_code (*open_port_f) (in_port_t, bool, in_port_t, uint16_t, std::string); // Open port on gateway
	typedef void (*close_port_f) (in_port_t, uint16_t, bool); // Close port on gateway
	typedef ioslaves::answer_code (*dns_srv_create_f) (const char*, std::string, std::string, bool, in_port_t, bool); // Create SRV entry (must be under ioslaves user for auth)
	typedef void (*dns_srv_del_f) (const char*, std::string, std::string, bool); // Delete SRV entry (must be under ioslaves user for auth)
	typedef void (*euid_switch_f) (uid_t, gid_t); // Switch EUIDs

}}
	
/// Definitions for ioslaves main program
#ifdef IOSLAVESD_API_MAIN_PROG

namespace ioslaves { namespace api {
	
	typedef bool (*start_f) (const char* by_master);
	typedef void (*set_callbacks_f) (ioslaves::service*, sig_atomic_t*, const char*, common_vars_t*,
												ioslaves::api::report_log_f, 
												ioslaves::api::open_port_f, ioslaves::api::close_port_f,
												ioslaves::api::dns_srv_create_f, ioslaves::api::dns_srv_del_f,
												ioslaves::api::euid_switch_f);
	typedef void (*net_client_call_f) (socketxx::base_socket&, const char* masterid, api_perm_t*, in_addr_t);
	typedef bool (*got_sigchld_f) (pid_t pid, int pid_status);
	typedef xif::polyvar* (*status_info_f) ();
	typedef bool (*shutdown_inhibit_f) ();
	typedef void (*stop_f) (void);
	
		// Callbacks to set
	#define IOSLAVED_API_MAIN_PROG_CALLBACKS_TO_SET                              \
		(ioslaves::api::report_log_f)ioslaves::api::report_log,                   \
		(ioslaves::api::open_port_f)ioslaves::api::open_port,                     \
		(ioslaves::api::close_port_f)ioslaves::api::close_port,                   \
		(ioslaves::api::dns_srv_create_f)ioslaves::api::dns_srv_create,           \
		(ioslaves::api::dns_srv_del_f)ioslaves::api::dns_srv_del,                 \
		(ioslaves::api::euid_switch_f)ioslaves::api::euid_switch                  \
		
	void report_log (ioslaves::service*, xlog::log_lvl, const char* part, std::string& msg, int f, xlog::logl_t*) noexcept;
	ioslaves::answer_code open_port (in_port_t ext, bool is_tcp, in_port_t loc, uint16_t range_sz, std::string descr) noexcept;
	void close_port (in_port_t ext, uint16_t range_sz, bool is_tcp) noexcept;
	ioslaves::answer_code dns_srv_create (const char* service_name, std::string domain, std::string host, bool with_cname, in_port_t port, bool is_tcp) noexcept;
	void dns_srv_del (const char* service_name, std::string domain, std::string host, bool is_tcp) noexcept;
	void euid_switch (uid_t, gid_t);
	
}}

#endif /* IOSLAVESD_API_MAIN_PROG */

/// Definitions for ioslaves plugin service
// Never trust other plugins and ioslavesd about global or side-effect operations or vars (like chdir...), and non reentrant functions

#ifdef IOSLAVESD_API_SERVICE

extern "C" {
	
		// Set callbacks
	void ioslapi_set_callbacks (ioslaves::service*, sig_atomic_t* _sigchild_p, const char* hostname, ioslaves::api::common_vars_t*,
										 ioslaves::api::report_log_f, 
										 ioslaves::api::open_port_f, ioslaves::api::close_port_f,
										 ioslaves::api::dns_srv_create_f, ioslaves::api::dns_srv_del_f,
										 ioslaves::api::euid_switch_f);
	bool ioslapi_start (const char* by_master); // Called at service start, when callbacks are defined (by_master = NULL if autostarted)
	void ioslapi_net_client_call (socketxx::base_socket&, const char* masterid, ioslaves::api::api_perm_t* perms, in_addr_t); // Network request from a master for the API service (perms = NULL if not authenticated, master ID can be empty)
	bool ioslapi_got_sigchld (pid_t pid, int pid_status); // Report that a SIGCHILD was catched for this pid with this status. Return true if the API service is the owner of the terminated process.
	xif::polyvar* ioslapi_status_info (); // Returns a small allocated resumé free format of the service's status
	bool ioslapi_shutdown_inhibit (); // Returns if service shutdown should be inhibited
	void ioslapi_stop (void); // Called at service stop (except when fatal was reported)
	
}

#ifndef IOSLAVESD_API_SERVICE_IMPL
	#define IOSLAVESD_API_SERVICE_EXTERN_SYMBOL extern
#else
	#define IOSLAVESD_API_SERVICE_EXTERN_SYMBOL
#endif

namespace ioslaves { namespace api {
	IOSLAVESD_API_SERVICE_EXTERN_SYMBOL ioslaves::service* service_me;
	IOSLAVESD_API_SERVICE_EXTERN_SYMBOL const char* slave_name;
	IOSLAVESD_API_SERVICE_EXTERN_SYMBOL common_vars_t* common_vars;
	IOSLAVESD_API_SERVICE_EXTERN_SYMBOL ioslaves::api::report_log_f report_log;
	IOSLAVESD_API_SERVICE_EXTERN_SYMBOL ioslaves::api::open_port_f open_port;
	IOSLAVESD_API_SERVICE_EXTERN_SYMBOL ioslaves::api::close_port_f close_port;
	IOSLAVESD_API_SERVICE_EXTERN_SYMBOL ioslaves::api::dns_srv_create_f dns_srv_create;
	IOSLAVESD_API_SERVICE_EXTERN_SYMBOL ioslaves::api::dns_srv_del_f dns_srv_del;
	IOSLAVESD_API_SERVICE_EXTERN_SYMBOL ioslaves::api::euid_switch_f euid_switch;
}}

#ifdef IOSLAVESD_API_SERVICE_IMPL

extern "C" void ioslapi_set_callbacks (ioslaves::service* _me, sig_atomic_t* _sigchild_p, const char* hostname, ioslaves::api::common_vars_t* _common_vars,
													ioslaves::api::report_log_f _report_log, 
													ioslaves::api::open_port_f _open_port, ioslaves::api::close_port_f _close_port,
													ioslaves::api::dns_srv_create_f _dns_srv_create, ioslaves::api::dns_srv_del_f _dns_srv_del,
													ioslaves::api::euid_switch_f _euid_switch) {
	ioslaves::api::service_me = _me;
	ioslaves::api::slave_name = hostname;
	signal_catch_sigchild_p = _sigchild_p;
	ioslaves::api::common_vars = _common_vars;
	ioslaves::api::report_log = _report_log;
	ioslaves::api::open_port = _open_port;
	ioslaves::api::close_port = _close_port;
	ioslaves::api::dns_srv_create = _dns_srv_create;
	ioslaves::api::dns_srv_del = _dns_srv_del;
	ioslaves::api::euid_switch = _euid_switch;
}

	// API Log
pthread_mutex_t xlog::logstream_impl::mutex = PTHREAD_MUTEX_INITIALIZER;
std::ostringstream xlog::logstream_impl::stream;
void xlog::logstream_impl::log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid) noexcept {
	(*ioslaves::api::report_log)(ioslaves::api::service_me, lvl, part, msg, m, lid);
}

#endif /* IOSLAVESD_API_SERVICE_IMPL */

#endif /* IOSLAVESD_API_SERVICE */

	// Run a block of code as root (errno is preserved, initial uid/gid restored)
#include <unistd.h>
struct _block_asroot {
	uid_t uid; gid_t gid;
	_block_asroot () { uid = ::geteuid(); gid = ::getegid(); ioslaves::api::euid_switch(0,0); }
	~_block_asroot () { ioslaves::api::euid_switch(uid, gid); }
};
#define asroot_block() _block_asroot _block_asroot_handle

#endif
