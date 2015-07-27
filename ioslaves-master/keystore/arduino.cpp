/**********************************************************\
 *               -== Xif Network project ==-
 *             ioslaves-master keystore plugin
 *        Arduino key storage and authentification
 * *********************************************************
 * Copyright © Félix Faisant 2015. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common
#include "common.hpp"
#define IOSL_MASTER_KEYSTORE_PLUGIN_IMPL
#include "keystore.hpp"

	// Key file
#define private public
#include <libconfig.h++>
#undef private

extern "C" void key_store (std::string key_id, ioslaves::key_t key, libconfig::Setting& data_write) {
	#warning TO DO
}

extern "C" ioslaves::hash_t key_answer_challenge (std::string key_id, ioslaves::challenge_t challenge, const libconfig::Setting& data) {
	#warning TO DO
}
