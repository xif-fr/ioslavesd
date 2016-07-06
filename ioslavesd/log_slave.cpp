/**********************************************************\
 *                  ioslaves : ioslavesd
 *         Log backbone implementation for ioslavesd
 * *********************************************************
 * Copyright © Félix Faisant 2013-2016. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common log interface
#define IOSLAVES_LOG_DEFAULT_LOGSTREAM_IMPL
#include "log_defimpl.h"
pthread_mutex_t xlog::logstream_impl::mutex = PTHREAD_MUTEX_INITIALIZER;
std::ostringstream xlog::logstream_impl::stream;

	// File
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

	// General and utils
#include <time.h>
#include <string.h>
#include <errno.h>
#include <vector>
#include <xifutils/cxx.hpp>
#include <xifutils/intstr.hpp>

	// ioslavesd interface
#include "main.h"
std::vector<log_entry> log_history;

#define STRFTIME_BUF_SIZE 30
#define LOG_DIFF_TIME_SHOW_SEC 1
fd_t fd_log = -1;
const char* log_file_path = NULL;
bool waiting_log = false;

struct log_display_info {
	const char* str;
	const char* color;
};
log_display_info log_display_infos[] = {
	{"FATAL",   "\033[1;31;4m\a" },
	{"ERROR",   "\033[1;31m"     },
	{"OOPS",    "\033[31m"       },
	{"SEVERE",  "\033[1;35m"     },
	{"WARNING", "\033[1;33m"     },
	{"NOTICE",  "\033[1;4m"      },
	{"LOG",     "\033[1m"        },
	{"IMP",     "\033[1;36m"     },
	{"MAJOR",   "\033[1;34m"     },
	{"DONE",    "\033[32m"       },
	{"DEBUG",   ""               },
	{NULL,      NULL             }
};

void xlog::logstream_impl::log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid) noexcept {
	timeval now;
	::gettimeofday(&now, NULL);
	log_display_info log_disp = log_display_infos[(size_t)lvl];
	std::string txt_output, tty_output;
	if (m & LOG_ADD) {
		if (lid == NULL) {
			xlog::logstream_impl::log(lvl, part, _S("...",msg), (m & ~LOG_ADD), NULL);
			return;
		} else {
			log_entry& le = log_history.at(*lid);
			std::string timestr = " ";
			time_t diff;
			if ((diff = now.tv_sec-le.le_time) > LOG_DIFF_TIME_SHOW_SEC)
				timestr = _S( " [+",::ixtoa(diff),"s] " );
			le.le_time = now.tv_sec;
			le.le_msg += _S( " […]",timestr,msg );
			bool same_line = (log_history.size()-1 == *lid);
			if (same_line && waiting_log) {
				txt_output = timestr + msg;
				tty_output = ((lvl != le.le_lvl and lvl != log_lvl::LOG and lvl != log_lvl::_DEBUG)
				              ? _S(log_disp.color) + timestr + msg + "\033[0m" 
				              : timestr + msg);
				if (log_callback) 
					log_callback(log_entry {
						.le_time = now.tv_sec,
						.le_msg = _S( "... ", msg ),
						.le_part = part,
						.le_lvl = lvl
					});
			} else {
				xlog::logstream_impl::log(lvl, le.le_part, _S( "[-",::ixtoa(log_history.size()-*lid),"l] ...",msg ), (m & ~LOG_ADD)|LOG_NO_HISTORY, lid);
				return;
			}
		}
	} else {
		if (waiting_log) {
			tty_output = txt_output = "\n";
			waiting_log = false;
		}
		log_entry new_le = {
			.le_time = now.tv_sec,
			.le_msg = msg,
			.le_part = part,
			.le_lvl = lvl
		};
		if (log_callback) 
			log_callback(new_le);
		if (not (m & LOG_NO_HISTORY)) {
			log_history.push_back(new_le);
			if (lid != NULL) *lid = (logl_t)log_history.size()-1;
		}
		tm gmt_time;
		time_t now = ::time(NULL);
		::gmtime_r(&now, &gmt_time);
		char time_str[STRFTIME_BUF_SIZE];
		::strftime(time_str, STRFTIME_BUF_SIZE, "%F %TZ ", &gmt_time);
		std::string intro;
		intro += time_str;
		if (part != NULL)
			intro += _S( "[",part,"] " );
		tty_output += _S( intro,log_disp.color,"[",log_disp.str,"]\033[0m ",msg );
		txt_output += _S( intro,"[",log_disp.str,"] ",msg );
		if (m & LOG_WAIT) 
			waiting_log = true;
	}
	if (not (m & LOG_WAIT)) {
		tty_output += '\n'; txt_output += '\n';
		waiting_log = false;
	}
	if (log_file_path != NULL) {
		ssize_t rs;
		if (fd_log == -1) {
		_reopen_log:
			fd_log = ::open(log_file_path, O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW, 0644);
			if (fd_log == -1) {
				::fprintf(stderr, "\n\t*** WARNING : LOG FILE COULDN'T BE OPENED ! %s\n\n\n", ::strerror(errno));
				fd_log = -2;
			} else 
				::write(fd_log, "\n\n===== LOG OPENED =====\n", 25);
		}
		if (fd_log != -2) {
			rs = ::write(fd_log, txt_output.c_str(), txt_output.length());
			if (rs != (ssize_t)txt_output.length()) {
				::close(fd_log);
				goto _reopen_log;
			}
		}
	}
	if (::isatty(STDERR_FILENO)) ::fputs(tty_output.c_str(), stderr);
	else                         ::fputs(txt_output.c_str(), stderr);
	::fflush(stderr);
}

