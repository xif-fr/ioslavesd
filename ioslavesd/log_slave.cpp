#include "log.h"
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <vector>
#include <xifutils/cxx.hpp>

struct log_display_info {
	const char* str;
	const char* color;
};

log_display_info log_display_infos[] = {
	{"FATAL",   "\033[1;31;4m\a" },
	{"ERROR",   "\033[1;31m"     },
	{"OOPS",    "\033[31m"       },
	{"WARNING", "\033[1;33m"     },
	{"NOTICE",  "\033[1;4m"      },
	{"LOG",     "\033[1m"        },
	{"IMP",     "\033[1;36m"     },
	{"MAJOR",   "\033[1;34m"     },
	{"DONE",    "\033[32m"       },
	{NULL,      NULL             }
};

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
std::ostringstream log_stream;
std::ostringstream& _log_get_tmp_stream () {
	pthread_mutex_lock(&log_mutex);
	log_stream.clear();
	log_stream.str(std::string());
	return log_stream;
}

std::vector<log_entry> log_history;

#define STRFTIME_BUF_SIZE 30
#define LOG_DIFF_TIME_SHOW_SEC 1
bool log_file_fail_warned = false;
const char* _log_file_path = NULL;
bool waiting_log = false;

void _log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid);

void __log__ (log_lvl lvl, const char* part, std::ostream&, int m, logl_t* lid)     { _log(lvl, part, log_stream.str(), m, lid); }
void __log__ (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid)   { pthread_mutex_lock(&log_mutex); _log(lvl, part, msg, m, lid); }

void _log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid) {
	#if !DEBUG
	if (m & LOG_DEBUG) {
		pthread_mutex_unlock(&log_mutex);
		return;
	}
	#endif
	log_display_info log_disp = log_display_infos[(size_t)lvl];
	std::string txt_output, tty_output;
	if (m & LOG_ADD) {
		if (lid == NULL) {
			_log(lvl, part, _S("...",msg), (m & ~LOG_ADD), NULL);
			return;
		} else {
			log_entry& le = log_history.at(*lid);
			std::string timestr = " ";
			time_t diff;
			if ((diff = ::time(NULL)-le.le_time) > LOG_DIFF_TIME_SHOW_SEC)
				timestr = _S( " [+",::ixtoa(diff),"s] " );
			le.le_time = ::time(NULL);
			le.le_msg += _S( " […]",timestr,msg );
			bool same_line = (log_history.size()-1 == *lid);
			if (same_line && waiting_log) {
				txt_output = timestr + msg;
				tty_output = ((lvl != le.le_lvl and lvl != log_lvl::LOG) 
				              ? _S(log_disp.color) + timestr + msg + "\033[0m" 
				              : timestr + msg);
			} else {
				_log(lvl, le.le_part, _S( "[-",::ixtoa(log_history.size()-*lid),"l] ...",msg ), (m & ~LOG_ADD)|LOG_NO_HISTORY, lid);
				return;
			}
		}
	} else {
		if (waiting_log) {
			tty_output = txt_output = "\n";
			waiting_log = false;
		}
		time_t now = ::time(NULL);
		if (not (m & LOG_NO_HISTORY)) {
			log_entry new_le;
			new_le.le_time = now;
			new_le.le_msg = msg;
			new_le.le_part = part;
			new_le.le_lvl = lvl;
			log_history.push_back(new_le);
			if (lid != NULL) *lid = (logl_t)log_history.size()-1;
		}
		tm gmt_time;
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
	if (_log_file_path != NULL) {
		FILE* log_file = ::fopen(_log_file_path, "a");
		if (log_file != NULL) {
			::fputs(txt_output.c_str(), log_file);
			::fclose(log_file);
		} else if (!log_file_fail_warned) {
			::fputs("\n\t*** WARNING : LOG FILE COULDN'T BE OPENED !\n\n", stderr);
			log_file_fail_warned = true;
		}
	}
	if (::isatty(STDERR_FILENO)) ::fputs(tty_output.c_str(), stderr);
	else                         ::fputs(txt_output.c_str(), stderr);
	::fflush(stderr);
	pthread_mutex_unlock(&log_mutex);
}

