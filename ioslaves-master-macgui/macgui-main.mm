/**********************************************************\
 *              ioslaves : XifNet Master.app
 *       ioslaves master graphical interface for OS X
 * *********************************************************
 * Copyright © Félix Faisant 2015-2016. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common
#include "common.hpp"
#include "master.hpp"
#include "macgui-common.h"
std::unordered_map<pthread_t,id<XifLogger>,std::hash<pthread_t>,equal_threads_t> thread_controllers;

	// Log
#include "log.h"
namespace xlog {
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	std::ostringstream stream;
}
std::ostream& xlog::logstream_acquire () noexcept {
	::pthread_mutex_lock(&xlog::mutex);
	return xlog::stream;
}
std::string xlog::logstream_retrieve () noexcept {
	std::string buf = xlog::stream.str();
	xlog::stream.str(std::string());
	::pthread_mutex_unlock(&xlog::mutex);
	return buf;
}
void xlog::__log__ (xlog::log_lvl lvl, const char* part, std::ostream&, int m, xlog::logl_t* lid) noexcept {
	xlog::__log__(lvl, part, xlog::logstream_retrieve(), m, lid);
}
void xlog::__log__ (xlog::log_lvl lvl, const char* part, std::string msg, int m, xlog::logl_t* lid) noexcept {
	id<XifLogger> ctrler = thread_controllers[::pthread_self()];
	::dispatch_sync(dispatch_get_main_queue(), ^{ // warning : deadlock possible
		[ctrler addLogLineAtTime:time(NULL) OfLevel:lvl isLocal:true inPart:(part==NULL?"":part) withMessage:msg];
	});
}

	// AppKit
#import <Cocoa/Cocoa.h>
int main (int argc, char* argv[]) {
	return NSApplicationMain(argc, (const char**)argv);
}
