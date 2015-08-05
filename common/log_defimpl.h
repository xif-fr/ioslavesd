#include "log.h"

#ifndef XIF_LOG_DEFAULT_LOGSTREAM_H
#define XIF_LOG_DEFAULT_LOGSTREAM_H

#include <string>
#include <pthread.h>
#include <sstream>

namespace xlog {
		
	namespace logstream_impl { // To be implemented
		
		extern pthread_mutex_t mutex;
		extern std::ostringstream stream;
		
		void log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid) noexcept;
		
	}
	
}

#endif

#ifdef XIF_LOG_DEFAULT_LOGSTREAM_IMPL

std::ostream& xlog::logstream_acquire () noexcept {
	::pthread_mutex_lock(&xlog::logstream_impl::mutex);
	xlog::logstream_impl::stream.str(std::string());
	return xlog::logstream_impl::stream;
}
std::string xlog::logstream_retrieve () noexcept {
	std::string buf = xlog::logstream_impl::stream.str();
	xlog::logstream_impl::stream.str(std::string());
	::pthread_mutex_unlock(&xlog::logstream_impl::mutex);
	return buf;
}

void xlog::__log__ (xlog::log_lvl lvl, const char* part, std::ostream&, int m, xlog::logl_t* lid) noexcept {
	xlog::logstream_impl::log(lvl, part, xlog::logstream_impl::stream.str(), m, lid);
	::pthread_mutex_unlock(&xlog::logstream_impl::mutex);
}
void xlog::__log__ (xlog::log_lvl lvl, const char* part, std::string msg, int m, xlog::logl_t* lid) noexcept {
	::pthread_mutex_lock(&xlog::logstream_impl::mutex);
	xlog::logstream_impl::log(lvl, part, msg, m, lid);
	::pthread_mutex_unlock(&xlog::logstream_impl::mutex);
}

#endif