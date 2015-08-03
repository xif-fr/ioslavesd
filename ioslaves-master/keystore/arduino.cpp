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

	// Arduino communication
#include "arduino_comm.h"
inline std::string arduinoCommGetAnswerCodeDescription (arduino_auth_answ o) {
	switch (o) {
		case arduino_auth_answ::OK: return "ok";
		case arduino_auth_answ::COMM_ERROR: return "communication error with the module";
		case arduino_auth_answ::EEPROM_ERROR: return "EEPROM error";
		case arduino_auth_answ::NO_MORE_SPACE: return "no more space for key storage";
		case arduino_auth_answ::NOT_FOUND: return "not found";
		case arduino_auth_answ::PASSWD_FAIL: return "user failed to input passcode";
		case arduino_auth_answ::ERROR: return "generic error";
	}
	return "unknown error";
}

	// Key storage implentation
extern "C" void key_store (std::string key_id, ioslaves::key_t key, libconfig::Setting& data_write) {
	#warning TO DO
}

	// Challenge answering implentation
extern "C" ioslaves::hash_t key_answer_challenge (std::string key_id, ioslaves::challenge_t challenge, const libconfig::Setting& data) {
	#warning TO DO
}
