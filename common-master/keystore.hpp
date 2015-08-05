/**********************************************************\
 *               -== Xif Network project ==-
 *             ioslaves-master common header
 *                Master key storage API
 * *********************************************************
 * Copyright © Félix Faisant 2015. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

#ifndef IOSLAVES_MASTER_COMMON_KEYSTORE_HPP
#define IOSLAVES_MASTER_COMMON_KEYSTORE_HPP

	// Common
#include "log.h"
#include "common.hpp"

	// Key file
namespace libconfig { class Setting; }

	/// Key storage API

namespace iosl_master {
	namespace keystore_api {
		
			// Storage method plugin's interface
		typedef void (*key_store_f) (std::string key_id, ioslaves::key_t key, libconfig::Setting& data_write);
		typedef ioslaves::hash_t (*key_answer_challenge_f) (std::string key_id, ioslaves::challenge_t challenge, const libconfig::Setting& data);
		
			// Provide access to master symbols
		struct callbacks {
			std::ostream& (*logstream_acquire) () noexcept;
			std::string (*logstream_retrieve) () noexcept;
			void (*log_ostream) (xlog::log_lvl, const char*, std::ostream&, int, xlog::logl_t*) noexcept;
			void (*log_string) (xlog::log_lvl, const char*, std::string, int, xlog::logl_t*) noexcept;
		};
	}
}

#ifdef IOSL_MASTER_KEYSTORE_PLUGIN_IMPL

extern "C" {
	void key_store (std::string key_id, ioslaves::key_t key, libconfig::Setting& data_write);
	ioslaves::hash_t key_answer_challenge (std::string key_id, ioslaves::challenge_t challenge, const libconfig::Setting& data);
	iosl_master::keystore_api::callbacks api_callbacks;
}

	// API Log
std::ostream& xlog::logstream_acquire () noexcept { return (*api_callbacks.logstream_acquire)(); }
std::string xlog::logstream_retrieve () noexcept { return (*api_callbacks.logstream_retrieve)(); }
void xlog::__log__ (xlog::log_lvl lvl, const char* part, std::ostream& s, int m, xlog::logl_t* lid) noexcept { (*api_callbacks.log_ostream)(lvl,part,s,m,lid); }
void xlog::__log__ (xlog::log_lvl lvl, const char* part, std::string msg, int m, xlog::logl_t* lid) noexcept { (*api_callbacks.log_string)(lvl,part,msg,m,lid); }

#endif

#endif
