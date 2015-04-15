#include "log.h"
#define IOSLAVESD_API_SERVICE
#include "api.h"
#include <pthread.h>

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
std::ostringstream log_stream;
std::ostringstream& _log_get_tmp_stream () {
	::pthread_mutex_lock(&log_mutex);
	log_stream.str("");
	return log_stream;
}

void _log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid);

void __log__ (log_lvl lvl, const char* part, std::ostream&, int m, logl_t* lid)     { _log(lvl, part, log_stream.str(), m, lid); }
void __log__ (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid)   { pthread_mutex_lock(&log_mutex); _log(lvl, part, msg, m, lid); }

void _log (log_lvl lvl, const char* part, std::string msg, int m, logl_t* lid) {
	(*ioslaves::api::callbacks::report_log)(ioslaves::api::service_me, lvl, part, msg, m, lid);
	::pthread_mutex_unlock(&log_mutex);
}
