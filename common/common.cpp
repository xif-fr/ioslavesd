#include "common.hpp"

	// General
#include <xifutils/cxx.hpp>
#include <xifutils/intstr.hpp>

	// OS headers
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

std::string ioslaves::getAnswerCodeDescription (ioslaves::answer_code o) {
	switch (o) {
		case ioslaves::answer_code::OK: return "ok";
		case ioslaves::answer_code::MAY_HAVE_FAIL: return "operation may have failed";
		case ioslaves::answer_code::INTERNAL_ERROR: return "slave internal/system error";
		case ioslaves::answer_code::SECURITY_ERROR: return "security error";
		case ioslaves::answer_code::NOT_AUTHORIZED: return "permission denied";
		case ioslaves::answer_code::BAD_CHALLENGE_ANSWER: return "bad answer to challenge";
		case ioslaves::answer_code::NOT_FOUND: return "not found";
		case ioslaves::answer_code::BAD_STATE: return "bad state";
		case ioslaves::answer_code::BAD_TYPE: return "bad type";
		case ioslaves::answer_code::WANT_REPORT: return "wants to report";
		case ioslaves::answer_code::WANT_GET: return "wants to get something";
		case ioslaves::answer_code::WANT_SEND: return "wants to send something";
		case ioslaves::answer_code::OP_NOT_DEF: return "operation not defined";
		case ioslaves::answer_code::EXISTS: return "already exists";
		case ioslaves::answer_code::UPNP_ERROR: return "port mapping error";
		case ioslaves::answer_code::DENY: return "refusal";
		case ioslaves::answer_code::INVALID_DATA: return "invalid data";
		case ioslaves::answer_code::LACK_RSRC: return "lacking ressources";
		case ioslaves::answer_code::EXTERNAL_ERROR: return "external error";
		case ioslaves::answer_code::TIMEOUT: return "timeout";
		case ioslaves::answer_code::ERROR: return "generic error";
	}
	return "unknown error";
}

time_t iosl_time () {
	#ifdef __MACH__
		struct timeval tv;
		::gettimeofday(&tv, NULL);
		return tv.tv_sec;
	#else
		#ifndef CLOCK_BOOTTIME
			#define CLOCK_BOOTTIME CLOCK_MONOTONIC
		#endif
		timespec ts;
		::clock_gettime(CLOCK_BOOTTIME, &ts);
		return ts.tv_sec;
	#endif
}

/** ------------------------------------	**/
/**           Strings validation				**/
/** ------------------------------------	**/

bool ioslaves::validateShellProgramName (std::string str) {
	if (str.empty()) return false;
	if (not ::isalpha(str[0])) return false;
	for (size_t i = 1; i < str.length(); ++i) {
		if (not (::isalnum(str[i]) || str[i] == '-' || str[i] == '_')) return false;
	}
	return true;
}

bool ioslaves::validateHexa (std::string hexa_str) {
	if (hexa_str.empty()) return false;
	for (size_t i = 0; i < hexa_str.length(); ++i) {
		if (not ((hexa_str[i] >= 0x30 and hexa_str[i] < 0x3A) or (hexa_str[i] > 0x40 and hexa_str[i] <= 0x46) or (hexa_str[i] > 0x60 and hexa_str[i] <= 0x66)))
			return false;
	}
	return true;
}

bool ioslaves::validateHostname (std::string host) {
	if (host.empty()) return false;
	for (size_t i = 0; i < host.length(); ++i) {
		if (not (::isalnum(host[i]) || host[i] == '-' || host[i] == '.'))
			return false;
	}
	return true;
}

bool ioslaves::validateName (std::string str) {
	if (str.empty()) return false;
	if (not ::isalpha(str[0])) return false;
	for (size_t i = 1; i < str.length(); ++i) {
		if (not (::isalnum(str[i]) || str[i] == '_')) return false;
	}
	return true;
}

bool ioslaves::validateSlaveName (std::string str) {
	if (str.empty()) return false;
	for (size_t i = 0; i < str.length(); ++i) {
		if (not (::isalpha(str[i]) || str[i] == '-')) return false;
	}
	return true;
}

bool ioslaves::validateMasterID (std::string str) {
	if (str.empty()) return false;
	if (::isdigit(str[0])) return false;
	for (size_t i = 0; i < str.length(); ++i) {
		if (not (::isalpha(str[i]) || str[i] == '-' || str[i] == '_')) return false;
	}
	return true;
}

/** ------------------------------------	**/
/**             Version class		    		**/
/** ------------------------------------	**/

ioslaves::version::version (std::string ver_str, bool poststr_ok) : _fullstr(ver_str), _major(0), _minor(0), _rev(0) {
	size_t i_field = 0;
	u_int* fields[] = { &this->_major, &this->_minor, &this->_rev, NULL };
	std::string field;
	size_t i;
	for (i = 0; i < ver_str.length(); i++) {
		if (ver_str[i] == '.') {
			if (field.empty()) throw std::runtime_error("str2version : field empty");
			else {
			transform:
				if (fields[i_field] == NULL) throw std::runtime_error("str2version : too many fields");
				*fields[i_field++] = ::atoix<u_int>(field, IX_DEC);
				field.clear();
			}
		}
		else if (::isdigit(ver_str[i])) 
			field += ver_str[i];
		else {
			if (not poststr_ok) throw std::runtime_error("str2version : illegal character");
			else break;
		}
	}
	i = ver_str.length();
	if (not field.empty()) goto transform;
	if (i_field < 1) throw std::runtime_error("str2version : incomplete version str");
}
std::string ioslaves::version::str () const {
	if (not _fullstr.empty()) 
		return this->_fullstr;
	else 
		return this->strdigits(false);
}
std::string ioslaves::version::strdigits (bool all) const {
	std::string v_str = ::ixtoa(this->_major) + '.' + ::ixtoa(this->_minor);
	if (this->_rev != 0 or all) {
		v_str += '.'; v_str += ::ixtoa(this->_rev);
	}
	return v_str;
}


/** ------------------------------------	**/
/**                Crypto     	   			**/
/** ------------------------------------	**/

#include <openssl/whrlpool.h>
#include <openssl/md5.h>

std::string ioslaves::bin_to_hex (const unsigned char* d, size_t sz) {
	std::string hex;
	for (size_t i = 0; i < sz; i++) 
		hex += ::ixtoap<unsigned char>(d[i], 2, IX_HEX);
	return hex;
}

void ioslaves::hex_to_bin (std::string hex, unsigned char* d) {
	if (hex.length()%2 != 0) 
		throw std::runtime_error("hex_to_bin: odd hex string length");
	for (size_t i = 0; i < hex.length()/2; i++) {
		d[i] = ::atoix<uint8_t>(hex.substr(2*i, 2), IX_HEX);
	}
}

std::string ioslaves::md5 (std::string to_hash) {
	unsigned char hashed[MD5_DIGEST_LENGTH];
	MD5((const unsigned char*)to_hash.c_str(), to_hash.length(), hashed);
	return bin_to_hex(hashed, sizeof(hashed));
}

unsigned char* ioslaves::generate_random (size_t sz) {
	fd_t fd = ::open("/dev/urandom", O_RDONLY);
	if (fd == INVALID_HANDLE) throw xif::sys_error("open(/dev/urandom) failed");
	RAII_AT_END_L( ::close(fd) );
	unsigned char* buf = new unsigned char[sz];
	if (::read(fd, buf, sz) != (ssize_t)sz) throw xif::sys_error("read(/dev/urandom) failed");
	return buf;
}

/** ------------------------------------	**/
/**           System functions          	**/
/** ------------------------------------	**/

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/wait.h>

	// Fork processus, change working dir, execute `cmd` with arguments, and redirect standard in/out to returned pipe
std::pair<pid_t,pipe_proc_t> ioslaves::fork_exec (const char* cmd, const std::vector<std::string>& args, bool io_redir, const char* wdir, bool closefds, uid_t uid, gid_t gid, bool disown) {
	int r;
	fd_t pipes_in[2], pipes_out[2], pipes_err[2];
	if (io_redir) {
		r = ::pipe(pipes_in) | ::pipe(pipes_out) | ::pipe(pipes_err);							// Create pipes pairs
		if (r == -1)
			throw xif::sys_error("can't create pipe pair for std in/out redirection with pipe()");
	} else {
		fd_t null = ::open("/dev/null", O_RDWR);														// Will redirect to /dev/null in place of pipes
		pipes_err[1] = pipes_out[1] = pipes_in[0] = null;
	}
	pid_t pid;
	pid = ::fork();																							// Fork processus
	if (pid > 0) {
		::close(pipes_err[1]); ::close(pipes_out[1]); ::close(pipes_in[0]);
		if (io_redir) 
			return std::pair<pid_t,pipe_proc_t>(pid, pipe_proc_t({pipes_in[1], pipes_out[0], pipes_err[0]}));
		else 
			return std::pair<pid_t,pipe_proc_t>(pid, pipe_proc_t({0,0,0}));
	} else if (pid == 0) {
		if (io_redir) {
			::close(pipes_err[0]); ::close(pipes_out[0]); ::close(pipes_in[1]);
		}
		if (::dup2(pipes_err[1], STDERR_FILENO) == -1 ||											// Redirect std in/out/err to pipe
			 ::dup2(pipes_out[1], STDOUT_FILENO) == -1 ||
			 ::dup2(pipes_in[0], STDIN_FILENO) == -1 ) 
		{ 
			::perror("fork_exec : can't redirect standard in/out with dup2()"); 
			::exit(EXIT_FAILURE);
		}
		if (closefds) {                                                                  // Close all inherited fds
#if HAS_CLOSEFROM
			::closefrom(3);
#else
			struct rlimit maxfd = {0, .rlim_max = (rlim_t)::sysconf(_SC_OPEN_MAX)};
			r = ::getrlimit(RLIMIT_NOFILE, &maxfd);
			if (r == -1 or RLIM_INFINITY == maxfd.rlim_max) maxfd.rlim_max = 4096;
			for (fd_t fd = 3; fd < (fd_t)maxfd.rlim_max; fd++)   // Vulnerble : fd higher than maxfd can exists
				::close(fd);
#endif
		}
		r = ::setregid(gid, gid) | ::setreuid(uid, uid);                                 // Set real+effective user and group IDs (-1 for no change)
		if (r == -1) { 
			::perror("fork_exec : can't set uid/gid"); 
			::exit(EXIT_FAILURE);
		}
		if (wdir != NULL) {
			r = ::chdir(wdir);																				// Change working directory
			if (r == -1) { 
				::perror("fork_exec : can't change working dir for java with chdir()"); 
				::exit(EXIT_FAILURE);
			}
		}
		if (disown) {
			r = ::setsid();																					// Create empty process session/group
			if (r == -1) { 
				::perror("fork_exec : can't change process session"); 
				::exit(EXIT_FAILURE);
			}
		}
		size_t argsz = args.size();																		// Arguments
		argsz++;																									// +1 for the first arg = cmd name
		char* * xargs = new char*[argsz+1];																// +1 for the last NULL
		xargs[0] = new char[::strlen(cmd)+1];
		::strcpy(xargs[0], cmd);
		for (size_t i = 1; i < argsz; ++i) {															// Copy arguments
			xargs[i] = new char[args[i-1].length()+1];
			::strcpy(xargs[i], args[i-1].c_str());
		}
		xargs[argsz] = NULL;
		r = ::execvp(cmd, xargs);																			// Execute
		::perror("fork_exec : failed to execute command with execvp()"); 
		::exit(EXIT_FAILURE);
	} else 
		throw xif::sys_error("can't fork() processus");
}

	// system(3) implementation, SIGCHILD must be blocked in other threads
int ioslaves::exec_wait (const char* cmd, const std::vector<std::string>& args, const char* wdir, uid_t uid, gid_t gid) {
	int r;
	pid_t pid = 
		ioslaves::fork_exec(cmd, args, false, wdir, true, uid, gid, false).first;
	int cmd_r = 0;
_rewait:
	r = ::waitpid(pid, &cmd_r, 0);
	if (r == -1) {
		if (errno == EINTR) goto _rewait;
		else throw xif::sys_error("exec_wait : waitpid failed");
	}
	return WEXITSTATUS(cmd_r);
}

#define DIRENT_ALLOC_SZ(dir) (size_t)offsetof(struct dirent, d_name) + std::max(sizeof(dirent::d_name), (size_t)::fpathconf(dirfd(dir),_PC_NAME_MAX)) +1

	// Remove folder entierely
void ioslaves::rmdir_recurse (const char* dir_path) {
	int r;
	DIR* dir = ::opendir(dir_path);
	if (dir == NULL) 
		throw xif::sys_error(_S("rmdir_recurse : can't open dir '",dir_path,"'"));
	dirent* dp, *dentr = (dirent*) ::malloc(DIRENT_ALLOC_SZ(dir));
	RAII_AT_END({
		::closedir(dir);
		::free(dentr);
	});
	int rr;
	while ((rr = ::readdir_r(dir, dentr, &dp)) != -1 and dp != NULL) {
		if (::strcmp(dp->d_name, ".") == 0 or ::strcmp(dp->d_name, "..") == 0) continue;
		char* path = new char[::strlen(dir_path)+::strlen(dp->d_name)+2];
		RAII_AT_END_L( delete[] path );
		::strcpy(path, dir_path);
		path[::strlen(dir_path)] = '/';
		::strcpy(path+::strlen(dir_path)+1, dp->d_name);
		struct stat info;
		r = ::lstat(path, &info);
		if (r == -1) 
			throw xif::sys_error(_S("rmdir_recurse : can't stat file '",path,"'"));
		if (S_ISDIR(info.st_mode)) {
			ioslaves::rmdir_recurse(path);	
		} else {
			r = ::unlink(path);
			if (r == -1) 
				throw xif::sys_error(_S("rmdir_recurse : can't remove file '",path,"'"));
		}
	}
	if (rr == -1)
		throw xif::sys_error("rmdir_recurse : readdir_r");
	r = ::rmdir(dir_path);
	if (r == -1) 
		throw xif::sys_error(_S("rmdir_recurse : can't remove directory '",dir_path,"'"));
}

	// Recursive chown
void ioslaves::chown_recurse (const char* dir_path, uid_t uid, gid_t gid) {
	int r;
	DIR* dir = ::opendir(dir_path);
	if (dir == NULL) 
		throw xif::sys_error(_S("chown_recurse : can't open dir '",dir_path,"'"));
	dirent* dp, *dentr = (dirent*) ::malloc(DIRENT_ALLOC_SZ(dir));
	RAII_AT_END({
		::closedir(dir);
		::free(dentr);
	});
	int rr;
	while ((rr = ::readdir_r(dir, dentr, &dp)) != -1 and dp != NULL) {
		if (::strcmp(dp->d_name, ".") == 0 or ::strcmp(dp->d_name, "..") == 0) continue;
		char* path = new char[::strlen(dir_path)+::strlen(dp->d_name)+2];
		RAII_AT_END_L( delete[] path );
		::strcpy(path, dir_path);
		path[::strlen(dir_path)] = '/';
		::strcpy(path+::strlen(dir_path)+1, dp->d_name);
		struct stat info;
		r = ::lstat(path, &info);
		if (r == -1) 
			throw xif::sys_error(_S("chown_recurse : can't stat file '",path,"'"));
		if (S_ISDIR(info.st_mode)) {
			ioslaves::chown_recurse(path, uid, gid);
		} else {
			r = ::lchown(path, uid, gid);
			if (r == -1) 
				throw xif::sys_error(_S("chown_recurse : can't chown file '",path,"'"));
		}
	}
	if (rr == -1)
		throw xif::sys_error("chown_recurse : readdir_r");
	r = ::lchown(dir_path, uid, gid);
	if (r == -1) 
		throw xif::sys_error(_S("chown_recurse : can't chown directory '",dir_path,"'"));
}

	// Get and cache home directory
const std::string& __get_homedir__() {
	static std::string __homedir;
	if (__homedir.empty()) {
		char* home = ::getenv("HOME");
		if (home != NULL and ::strlen(home) != 0) __homedir = home;
		else {
			struct passwd* pw = ::getpwuid(::getuid());
			if (pw == NULL) throw xif::sys_error("getpwuid");
			__homedir = pw->pw_dir;
		}
	}
	return __homedir;
}

/** -----------------------------	**/
/**          Info files         	**/
/** -----------------------------	**/

std::string ioslaves::infofile_get (const char* path, bool nul_if_no_file) {
	fd_t f = ::open(path, O_RDONLY);
	if (f == -1) {
		if (nul_if_no_file and errno == ENOENT) return std::string();
		throw xif::sys_error(_S("can't open infofile ",path));
	}
	RAII_AT_END_L( ::close(f) );
	size_t sz = ::lseek(f, 0, SEEK_END);
	if (sz == 0)
		return std::string();
	::lseek(f, 0, SEEK_SET);
	char* info = new char[sz+1];
	RAII_AT_END_N(info, {
		delete[] info;
	});
	ssize_t rs = ::read(f, info, sz);
	if (rs != (ssize_t)sz) 
		throw xif::sys_error("failed to read from infofile");
	info[sz] = '\0';
	for (size_t i = 0; i < sz; i++) 
		if (info[i] == '\n') { info[sz] = '\0'; break; }
	return std::string(info, ::strlen(info));
}

void ioslaves::infofile_set (const char* path, std::string info) {
	fd_t f = ::open(path, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (f == -1)
		throw xif::sys_error("can't open/create infofile");
	RAII_AT_END_L( ::close(f) );
	ssize_t rs = ::write(f, info.c_str(), info.length());
	if (rs != (ssize_t)info.length()) 
		throw xif::sys_error("failed to write to infofile");
}
