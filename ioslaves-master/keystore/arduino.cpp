/**********************************************************\
 *               -== Xif Network project ==-
 *             ioslaves-master keystore plugin
 *        Arduino key storage and authentification
 * *********************************************************
 * Copyright © Félix Faisant 2015. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common
#include "log.h"
using namespace xlog;
#include "common.hpp"
#include <xifutils/cxx.hpp>
#define IOSL_MASTER_KEYSTORE_PLUGIN_IMPL
#include "keystore.hpp"

	// General
#include <iostream>

	// Key file
#define private public
#include <libconfig.h++>
#undef private

	// Protocol
#include "arduino_comm.h"
inline std::string arduino_comm_get_answercode_descr (arduino_auth_answ o) {
	switch (o) {
		case arduino_auth_answ::OK: return "ok";
		case arduino_auth_answ::COMM_ERROR: return "communication error with the module";
		case arduino_auth_answ::EEPROM_ERROR: return "EEPROM error";
		case arduino_auth_answ::NO_MORE_SPACE: return "no more space for key storage";
		case arduino_auth_answ::NOT_FOUND: return "not found";
		case arduino_auth_answ::PASSWD_FAIL: return "user failed to input passcode";
		case arduino_auth_answ::ERROR: return "generic error";
		default: return "unknown error";
	}
}

	// Arduino serial connection
#include <termios.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/stat.h>
fd_t arduino_get_connection (const char* device, arduino_auth_opcode op);
uint8_t arduino_read_byte (fd_t serial, timeval timeout);
void arduino_write_str (fd_t serial, const std::string& str, uint8_t maxsz);

	// Key storage implentation
extern "C" void key_store (std::string key_id, ioslaves::key_t key, libconfig::Setting& data_write) {
	__log__(log_lvl::LOG, "ARDUINO", logstream << "Storing key '" << key_id << "' on arduino authentification module...");
	int r;
	size_t rs;
	std::string device = 
		ioslaves::infofile_get(IOSL_MASTER_KEYSTORE_ARDUINO_DEVICE_PATH_FILE, true);
	if (device.empty()) {
		if (not ::isatty(STDOUT_FILENO)) 
			throw std::runtime_error("arduino device path file doesn't exist");
		else {
			std::cout << "Value for arduino device path is not defined. Please enter the device path : ";
			std::getline(std::cin, device);
			struct stat devinfo;
			errno = EINVAL;
			r = ::lstat(device.c_str(), &devinfo);
			if (r == -1) 
				throw xif::sys_error("entered path is not valid");
			if (not S_ISCHR(devinfo.st_mode)) 
				throw xif::sys_error("entered file is not a serial device");
			ioslaves::infofile_set(IOSL_MASTER_KEYSTORE_ARDUINO_DEVICE_PATH_FILE, device);
		}
	}
	fd_t serial;
	try {
		serial = ::arduino_get_connection(device.c_str(), 
		                                  arduino_auth_opcode::OP_ADD_KEY);
	} catch (std::runtime_error& e) {
		throw std::runtime_error(logstream << "failed to connect to arduino : " << e.what() << logstr);
	}
	RAII_AT_END_L( ::close(serial) );
	::arduino_write_str(serial, key_id, KEY_ID_MAX_SZ);
	arduino_auth_answ o;
	o = (arduino_auth_answ)::arduino_read_byte(serial, ARDUINO_TIMEOUT);
	if (o != arduino_auth_answ::OK) 
		throw std::runtime_error(logstream << "key adding for '" << key_id << "' is not accepted by arduino : " << arduino_comm_get_answercode_descr(o) << logstr);
	uint8_t key_slot = ::arduino_read_byte(serial, ARDUINO_TIMEOUT);
	__log__(log_lvl::IMPORTANT, "ARDUINO", logstream << "Sending key '" << key_id << "' to arduino for storing on key slot n°" << (int)key_slot);
	for (size_t i = 0; i < KEY_SZ; i++) {
		rs = ::write(serial, &(key.bin[i]), 1);
		if (rs != 1) 
			throw xif::sys_error("failed to write key to arduino");
		::usleep(ARDUINO_WRITE_KEY_BYTE_DELAY);
	}
	o = (arduino_auth_answ)::arduino_read_byte(serial, ARDUINO_TIMEOUT);
	if (o != arduino_auth_answ::OK) 
		throw std::runtime_error(arduino_comm_get_answercode_descr("error while storing key", o));
	o = (arduino_auth_answ)::arduino_read_byte(serial, ARDUINO_TIMEOUT);
	if (o != arduino_auth_answ::OK) 
		throw std::runtime_error(arduino_comm_get_answercode_descr("error while writing index", o));
	__log__(log_lvl::DONE, "ARDUINO", logstream << "Key stored on Arduino !");
}

	// Challenge answering implentation
extern "C" ioslaves::hash_t key_answer_challenge (std::string key_id, ioslaves::challenge_t challenge, const libconfig::Setting& data) {
	fd_t serial = 
		::arduino_get_connection( ioslaves::infofile_get(IOSL_MASTER_KEYSTORE_ARDUINO_DEVICE_PATH_FILE, false).c_str(), 
		                          arduino_auth_opcode::OP_CHALLENGE);
	::arduino_write_str(serial, key_id, KEY_ID_MAX_SZ);
	arduino_auth_answ o;
	o = (arduino_auth_answ)::arduino_read_byte(serial, ARDUINO_TIMEOUT);
	if (o != arduino_auth_answ::OK) 
		throw std::runtime_error(logstream << "challenge resolving for '" << key_id << "' is not accepted by arduino" << arduino_comm_get_answercode_descr(o) << logstr);
	uint8_t key_slot = ::arduino_read_byte(serial, ARDUINO_TIMEOUT);
	__log__(log_lvl::IMPORTANT, "ARDUINO", logstream << "Sending challenge to arduino for resolving with key '" << key_id << "' on slot n°" << (int)key_slot);
	ssize_t rs;
	for (size_t i = 0; i < CHALLENGE_SZ; i++) {
		rs = ::write(serial, &(challenge.bin[i]), 1);
		if (rs != 1) 
			throw xif::sys_error("failed to write challenge to arduino");
		::usleep(ARDUINO_CHALLENGE_SEND_BYTE_DELAY);
	}
	o = (arduino_auth_answ)::arduino_read_byte(serial, ARDUINO_TIMEOUT);
	if (o != arduino_auth_answ::OK) 
		throw std::runtime_error(arduino_comm_get_answercode_descr("error while hashing challenge+key on arduino", o));
	ioslaves::hash_t hash;
	for (size_t i = 0; i < HASH_LEN; i++) {
		hash.bin[i] = ::arduino_read_byte(serial, ARDUINO_TIMEOUT);
	}
	return hash;
}

	// Get serial connection with Arduino
fd_t arduino_get_connection (const char* device, arduino_auth_opcode op) {
	__log__(log_lvl::LOG, "ARDUINO", logstream << "Connecting to arduino device " << device << " ...");
	int r;
	fd_t serial = ::open(device, O_RDWR|O_NOCTTY|O_NDELAY);
	if (serial == -1) 
		throw xif::sys_error("failed to open tty to device");
	bool keepco = false;
	RAII_AT_END({
		if (not keepco) 
			::close(serial);
	});
	r = ::fcntl(serial, F_SETFL, 0);
	if (r == -1) 
		throw xif::sys_error("failed to fcntl serial tty");
	struct termios tty;
	r = ::tcgetattr(serial, &tty);
	if (r == -1) 
		throw xif::sys_error("failed to get serial tty attrs");
	::cfmakeraw(&tty);
	::cfsetospeed(&tty, (speed_t)B9600);
	::cfsetispeed(&tty, (speed_t)B9600);
	tty.c_lflag = 0;
	tty.c_oflag = 0;
	tty.c_cflag |= (CLOCAL|CREAD);
	tty.c_cflag &= ~(PARENB|PARODD|CSTOPB|CRTSCTS);
	tty.c_cflag &= ~HUPCL;
	r = ::tcsetattr(serial, TCSANOW, &tty);
	if (r == -1) 
		throw xif::sys_error("failed to get serial tty attrs");
	try {
		::arduino_read_byte(serial, ARDUINO_CONNECTION_TIMEOUT);
	} catch (xif::sys_error&) { throw; }
	  catch (std::runtime_error&) {
		throw std::runtime_error("connection to arduino timed out");
	}
	ssize_t rs;
	uint8_t b = (uint8_t)op;
	rs = ::write(serial, &b, sizeof(b));
	if (rs != sizeof(b))
		throw xif::sys_error("failed to send opcode");
	arduino_auth_answ o;
	o = (arduino_auth_answ)::arduino_read_byte(serial, ARDUINO_PASSWD_TIMEOUT);
	o = (arduino_auth_answ)b;
	if (o != arduino_auth_answ::OK) 
		std::runtime_error(arduino_comm_get_answercode_descr("arduino module refused operation", o));
	__log__(log_lvl::DONE, "ARDUINO", logstream << "Operation accepted");
	keepco = true;
	return serial;
}
	// Read a byte from serial connection
uint8_t arduino_read_byte (fd_t serial, timeval timeout) {
	fd_set set;
	int r_sel;
	FD_ZERO(&set);
	FD_SET(serial, &set);
	errno = 0;
	r_sel = ::select(serial+1, &set, NULL, NULL, &timeout);
	if (r_sel == 0) 
		throw std::runtime_error("timeout while reading from arduino");
	if (r_sel != 1) {
		if (errno == EINTR) return arduino_read_byte(serial, timeout);
		throw xif::sys_error("select() on serial fd failed");
	}
	uint8_t b;
	size_t rs = ::read(serial, &b, sizeof(b));
	if (rs != sizeof(b)) 
		throw xif::sys_error("failed to read from arduino");
	return b;
}
	// Write a string to the Arduino (255 chars max)
void arduino_write_str (fd_t serial, const std::string& str, uint8_t maxsz) {
	if (str.length() > maxsz) 
		throw std::runtime_error("name too long");
	uint8_t sz = (uint8_t)str.length();
	ssize_t rs;
	rs = ::write(serial, &sz, sizeof(sz));
	if (rs != sizeof(sz)) 
		goto wrerr;
	rs = ::write(serial, str.c_str(), str.length());
	if (rs != sz) 
		goto wrerr;
	return;
wrerr:
	throw xif::sys_error("failed to write to arduino");
}