#ifndef _XIF_LOG_H
#define _XIF_LOG_H

#include <sstream>
#include <string>
#include <vector>

enum class log_lvl : unsigned char {
	FATAL = 0,
	ERROR = 1,
	OOPS = 2,
	WARNING = 3,
	NOTICE = 4,
	LOG = 5,
	IMPORTANT = 6,
	MAJOR = 7,
	DONE = 8,
};

std::ostringstream& _log_get_tmp_stream ();
#define logstream _log_get_tmp_stream()

typedef size_t logl_t;

#define LOG_WAIT         0x01
#define LOG_ADD          0x02
#define LOG_DEBUG        0x04
#define LOG_NO_HISTORY   0x08

void __log__ (log_lvl lvl, const char* part, std::string msg, int m = 0, logl_t* lid = NULL);
void __log__ (log_lvl lvl, const char* part, std::ostream&, int m = 0, logl_t* lid = NULL);

struct log_entry {
	time_t le_time;
	const char* le_part;
	std::string le_msg;
	log_lvl le_lvl;
};
	
extern std::vector<log_entry> log_history;

extern const char* _log_file_path;

#endif
