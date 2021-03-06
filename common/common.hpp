/**********************************************************\
 *                        ioslaves
 *    Common ioslaves utility and communication routines
 * *********************************************************
 * Copyright © Félix Faisant 2013-2016. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

#ifndef IOSLAVES_COMMON_HPP
#define IOSLAVES_COMMON_HPP

	// General
#include <string>
#include <inttypes.h>
#include <vector>

	// Mutex
#include <pthread.h>
#ifdef PTHREAD_MUTEX_LOG_ENABLED
	void pthread_mutex_log (void* obj, const char* action, pthread_mutex_t* mutex);
#else
	#define pthread_mutex_log(a,b,c)
#endif
class pthread_mutex_handle { // Shall be used/copied only in the same thread
	pthread_mutex_t* const _mutex;
	bool* _locked;
public:
	pthread_mutex_handle (pthread_mutex_t* mutex) : _mutex(mutex), _locked(new bool (true)) { pthread_mutex_log(this,"will lock",_mutex); ::pthread_mutex_lock(_mutex); pthread_mutex_log(this,"locked",_mutex); }
	pthread_mutex_handle (const pthread_mutex_handle& oth) = delete;
	void soon_unlock () { ::pthread_mutex_unlock(_mutex); *_locked = false; pthread_mutex_log(this,"soon unlocked",_mutex); }
	~pthread_mutex_handle () { if (*_locked) { ::pthread_mutex_unlock(_mutex); pthread_mutex_log(this,"auto unlocked",_mutex); } delete _locked; }
};
#define pthread_mutex_handle_lock(mutex) pthread_mutex_handle _mutex_handle_ (&mutex)

	// Time
#include <time.h>
#include <sys/time.h>
#define IOSLAVES_MASTER_MAX_UTC_DIFF_TIME 3
time_t iosl_time ();

	// Files
const std::string& __get_homedir__();
#ifdef __APPLE__
#define st_mtime st_mtimespec.tv_sec
#endif

	// Network
#include <../lib/socket++/include/config.h>
#include <socket++/defs.hpp>
#define INVALID_HANDLE (-1)
struct pipe_proc_t { fd_t in; fd_t out; fd_t err; };
char __read_pipe_state__ (fd_t pipe, time_t tm_sec, char def);

	// Log
#include "log.h"

namespace ioslaves {
	
		// ioslaves operations
	enum class op_code : char {
		SERVICE_START = 'a',
		SERVICE_STOP = 'o',
		IGD_PORT_OPEN = 'p',
		IGD_PORT_CLOSE = 'c',
		SLAVE_SHUTDOWN = 's',
		SHUTDOWN_CTRL = 'u',
		SLAVE_REBOOT = 'r',
		GET_STATUS = 'g',
		PERM_STATUS = 'S',
		CALL_API_SERVICE = 'l',
		LOG_HISTORY = 'h',
		LOG_OBSERVE = 'L',
		KEY_AUTH = 'k',
		KEY_DEL = 'd',
		NOP = '-'
	};
	
		// Authentication - Keys - Crypto
	#define HASH_LEN 64
	#define MD5_HEX_LEN 32
	#define KEY_LEN 256
	#define CHALLENGE_LEN 256
	#define IOSLAVES_KEY_SEND_DELAY 4
	std::string bin_to_hex (const unsigned char* d, size_t sz);
	void hex_to_bin (std::string, unsigned char* d);
	std::unique_ptr<unsigned char[]> generate_random (size_t sz);
	std::string md5 (std::string to_hash);
	struct key_t { unsigned char bin [KEY_LEN]; };
	struct challenge_t { unsigned char bin [CHALLENGE_LEN]; };
	struct hash_t { unsigned char bin [HASH_LEN]; };
	
		// Universal answer code (0 is reserved)
	enum class answer_code : char { 
		OK = '|',
		MAY_HAVE_FAIL = 'M',
		ERROR = '*',
		INTERNAL_ERROR = 'i',
		BAD_CHALLENGE_ANSWER = 'c',
		NOT_AUTHORIZED = '#',
		SECURITY_ERROR = 'r',
		NOT_FOUND = 'f',
		EXTERNAL_ERROR = 'e',
		BAD_STATE = 's',
		BAD_TYPE = 't',
		WANT_GET = 'W',
		WANT_SEND = 'S',
		WANT_REPORT = 'R',
		OP_NOT_DEF = 'o',
		EXISTS = 'E',
		UPNP_ERROR = 'U',
		DENY = 'D',
		INVALID_DATA = 'I',
		LACK_RSRC = 'k',
		TIMEOUT = 'T'
	};
	std::string getAnswerCodeDescription (ioslaves::answer_code);
		
		// Validating names or IDs
	bool validateHexa (std::string hexa_str);
	bool validateName (std::string id_str);
	bool validateServiceName (std::string str);
	bool validateHostname (std::string host);
	bool validateSlaveName (std::string str);
	bool validateMasterID (std::string master_id);
		
		// Exceptions
	class req_err : public std::exception {
	public:
		ioslaves::answer_code answ_code;
		std::string descr;
		req_err (answer_code answ, std::string msg) noexcept : answ_code(answ), descr(msg) {}
		req_err (answer_code answ, std::ostream&) noexcept : answ_code(answ), descr(xlog::logstream_retrieve()) {}
		req_err (answer_code answ, const char* part, std::string msg, xlog::log_lvl lvl = xlog::log_lvl::ERROR) noexcept : answ_code(answ), descr(msg) { xlog::__log__(lvl, part, msg); }
		req_err (answer_code answ, const char* part, std::ostream&, xlog::log_lvl lvl = xlog::log_lvl::ERROR) noexcept : answ_code(answ), descr(xlog::logstream_retrieve()) { xlog::__log__(lvl, part, descr); }
		virtual const char* what () const noexcept { return descr.c_str(); }
		virtual ~req_err() {}
	};
	
		// Version object
	struct version {
		std::string _fullstr;
		u_int _major, _minor, _rev;
		version () = delete;
		version (u_int v_major, u_int v_minor, u_int v_rev) : _major(v_major), _minor(v_minor), _rev(v_rev) {}
		explicit version (std::string ver_str, bool poststr_ok = true);
		bool operator<= (const version& ver) const { return not (this->_major > ver._major or this->_minor > ver._minor or this->_rev > ver._rev); }
		bool operator== (const version& ver) const { return (_major == ver._major and _minor == ver._minor and _rev == ver._rev); }
		std::string str () const;
		std::string strdigits (bool all = false) const;
	};
	inline bool operator>= (const version& ver1, const version& ver2) { return (ver1 == ver2 or ver2 <= ver1); }
	
		// Execute program `cmd` with arguments in defined working directory, and redirect standard in/out to returned pipe
	std::pair<pid_t,pipe_proc_t> fork_exec (const char* cmd, const std::vector<std::string>& args, bool io_redir, const char* wdir, bool closefds, uid_t uid, gid_t gid, bool disown, const char* locale);
		// system(3) implementation, SIGCHILD must be blocked in other threads
	int exec_wait (const char* cmd, const std::vector<std::string>& args, const char* wdir, uid_t uid, gid_t gid);
		
		// Filesystem utilities
	void rmdir_recurse (const char* folder_path);
	void chown_recurse (const char* folder_path, uid_t uid, gid_t gid);
	
		// Info file
	std::string infofile_get (const char* path, bool nul_if_no_file);
	void infofile_set (const char* path, std::string info);
	
}
		
#endif
