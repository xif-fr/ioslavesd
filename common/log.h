/**********************************************************\
 *                       ioslaves
 *              Log common interface and defs
 * *********************************************************
 * Copyright © Félix Faisant 2013-2016. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

#ifndef IOSLAVES_LOG_H
#define IOSLAVES_LOG_H

#include <ostream>
#include <string>

namespace xlog {

enum class log_lvl : unsigned char {
	FATAL = 0,
	ERROR = 1,
	OOPS = 2,
	SEVERE = 3,
	WARNING = 4,
	NOTICE = 5,
	LOG = 6,
	IMPORTANT = 7,
	MAJOR = 8,
	DONE = 9,
	VERBOSE = 10,
};

std::ostream& logstream_acquire () noexcept;
#define logstream xlog::logstream_acquire()
std::string logstream_retrieve () noexcept;
struct stream_manip_logstr { int foo; };
#define logstr xlog::stream_manip_logstr{0}

typedef size_t logl_t;

#define LOG_WAIT         0x01
#define LOG_ADD          0x02
#define LOG_DEBUG        0x04
#define LOG_NO_HISTORY   0x08

void __log__ (log_lvl, const char* part, std::ostream&, int flags = 0, logl_t* lid = NULL) noexcept;
void __log__ (log_lvl, const char* part, std::string msg, int flags = 0, logl_t* lid = NULL) noexcept;

}

inline std::string operator<< (std::ostream&, xlog::stream_manip_logstr) {
	return xlog::logstream_retrieve();
}
	
#endif
