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
#include "common.hpp"
#include "master.hpp"

	// Key file
namespace libconfig { class Setting; }

	/// Key storage API

namespace iosl_master {
	namespace keystore_api {
		
			// Storage method plugin's interface
		typedef void (*key_store_f) (std::string key_id, ioslaves::key_t key, libconfig::Setting& data_write);
		typedef ioslaves::hash_t (*key_answer_challenge_f) (std::string key_id, ioslaves::challenge_t challenge, const libconfig::Setting& data);
		
	}
}

#ifdef IOSL_MASTER_KEYSTORE_PLUGIN_IMPL

extern "C" {
	void key_store (std::string key_id, ioslaves::key_t key, libconfig::Setting& data_write);
	ioslaves::hash_t key_answer_challenge (std::string key_id, ioslaves::challenge_t challenge, const libconfig::Setting& data);
}

#endif

#endif
