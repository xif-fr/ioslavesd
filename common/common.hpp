/**********************************************************\
 *               -== Xif Network project ==-
 *                        ioslaves
 *            Control interface for XifNet services
 * 
 *            Common interface for communication 
 * *********************************************************
 * Copyright © Félix Faisant 2013-2014. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

#ifndef IOSLAVES_COMMON_HPP
#define IOSLAVES_COMMON_HPP

	// General
#include <string>
#include <inttypes.h>
#include <vector>

	// Log
#include "log.h"

	// Time
#include <sys/time.h>
#include <time.h>
#define IOSLAVES_MASTER_MAX_UTC_DIFF_TIME 3

	// Files
const std::string& __get_homedir__();

	// Network
#include <../lib/socket++/include/config.h>
#include <socket++/base_inet.hpp>
#include <socket++/io/simple_socket.hpp>
#include <socket++/quickdefs.h>
struct pipe_proc_t { fd_t in; fd_t out; fd_t err; }; 

#ifdef XIFNET
	#define XIFNET_SLAVES_DOM "net.xif.fr"
#endif

	// Keys
#define IOSLAVES_KEY_SIZE 256
#define IOSLAVES_CHALLENGE_SIZE 128

namespace ioslaves {
	
		// ioslaves Opperations
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
		LOG_HISTORY = 'h'
	};
	
		// Authentification - Crypto
	std::string generate_random (size_t sz);
	#define HASH_HEX_DIGEST_LENGHT 128
	std::string hash (std::string to_hash);
	std::string md5 (std::string to_hash);
	
		// Universal answer code (0 is reserved)
	enum class answer_code : char { 
		OK = '|', 
		MAY_HAVE_FAIL = 'M',
		ERROR = '*',
		INTERNAL_ERROR = 'i', 
		BAD_CHALLENGE_ANSWER = 'c', 
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
		LACK_RSRC = 'k'
	};
		
		// Validating names or IDs
	bool validateShellProgramName (std::string prog_name);
	bool validateHexa (std::string hexa_str);
	bool validateName (std::string id_str);
	bool validateHostname (std::string host);
	bool validateSlaveName (std::string str);
		
		// Exceptions
	class req_err : public std::exception {
	public:
		ioslaves::answer_code answ_code;
		std::string descr;
		req_err (answer_code answ, std::string msg) noexcept : answ_code(answ), descr(msg) {}
		req_err (answer_code answ, std::ostream& s) noexcept : answ_code(answ), descr(xlog::logstream_retrieve()) {}
		req_err (answer_code answ, const char* part, std::string msg) noexcept : answ_code(answ), descr(msg) { xlog::__log__(xlog::log_lvl::ERROR, part, msg); }
		req_err (answer_code answ, const char* part, std::ostream& s) noexcept : answ_code(answ), descr(xlog::logstream_retrieve()) { xlog::__log__(xlog::log_lvl::ERROR, part, descr); }
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
	std::pair<pid_t,pipe_proc_t> fork_exec (const char* cmd, const std::vector<std::string>& args, bool io_redir, const char* wdir, bool closefds, uid_t uid, gid_t gid, bool disown);
		
		// Filesystem utilities
	void rmdir_recurse (const char* folder_path);
	void chown_recurse (const char* folder_path, uid_t uid, gid_t gid);
	
		// Info file
	std::string infofile_get (const char* path, bool nul_if_no_file);
	void infofile_set (const char* path, std::string info);
	
}
		
#endif
