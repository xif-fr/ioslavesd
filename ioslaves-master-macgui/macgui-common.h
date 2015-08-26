#ifndef XIF_MACGUI_COMMON_H
#define XIF_MACGUI_COMMON_H

#import <AppKit/NSImage.h>
namespace icons {
	extern NSImage* unreachable;
	extern NSImage* down;
	extern NSImage* error;
	extern NSImage* up;
	extern NSImage* neterr;
	extern NSImage* forbidden;
	extern NSImage* syserr;
	extern NSImage* autherr;
	extern NSImage* disconnected;
}

extern sig_atomic_t slaves_init_conn_countdown;

#include <string>
#include "log.h"
@protocol XifLogger
@required
- (void)addLogLineAtTime:(time_t)time OfLevel:(xlog::log_lvl)lvl isLocal:(bool)local inPart:(std::string)part withMessage:(std::string)msg;
@end
#include <unordered_map>
#include <pthread.h>
struct equal_threads_t : public std::binary_function<pthread_t,pthread_t,bool> {
	bool operator() (const pthread_t& x, const pthread_t& y) const { return ::pthread_equal(x, y); }
};
extern std::unordered_map<pthread_t,id<XifLogger>,std::hash<pthread_t>,equal_threads_t> thread_controllers;

#endif