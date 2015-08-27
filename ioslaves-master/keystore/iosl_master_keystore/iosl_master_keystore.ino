/**
 *  For Arduino Mega with Atmel 24C64AN = 8192 bytes
 *  Can store a 512B index and 30x 256B keys
 *
 *  0x0000 /
 *    |    | { [slave_id \0][keynum_uint8] } x ...
 *   512B  |
 *    |    \_
 *  0x0200 /
 *         \_  keynum=0 256B key
 *  0x0300 /
 *         \_  keynum=1 256B key
 *  0x0400 /
 *         \_  keynum=2 256B key
 *  0x0500 /
 *  .      .
 *  .      .
 *  .      \_
 *  0x1800 /
 *         \_  keynum=28 256B key
 *  0x1900 /
 *  0x1999 \_  keynum=29 256B key
 *
 */

	// Communication
#include "[path]/ioslaves/ioslaves-master/keystore/arduino_comm.h"

	// Whirpool hash
#include <ArduinoWhirpool.h>

	// EEPROM
#include <Wire.h>
typedef unsigned int romaddr_t;
namespace eeprom {
	const uint8_t I2C_EEPROM_ADDR = 0x50;
	const unsigned int SZ = 0x2000; //B
	const romaddr_t IDX_ADDR = 0x0;
	const unsigned int IDX_SZ = 512; //B
	const romaddr_t KEYS_BEG = 0x200;
	const uint8_t KEYS_NUM = 30;
	const short WRITE_DELAY_MS = 3; //ms
	byte i2c_eeprom_read_byte (int device_addr, romaddr_t data_addr);
	void i2c_eeprom_write_byte (int device_addr, romaddr_t data_addr, byte b);
}
byte eeprom::i2c_eeprom_read_byte (int device_addr, romaddr_t data_addr) {
	Wire.beginTransmission(device_addr);
	Wire.write((int)(data_addr >> 8));
	Wire.write((int)(data_addr & 0xFF));
	Wire.endTransmission();
	Wire.requestFrom(device_addr, 1);
	while (!Wire.available());
	return Wire.read();
}
void eeprom::i2c_eeprom_write_byte (int device_addr, romaddr_t data_addr, byte b) {
	Wire.beginTransmission(device_addr);
	Wire.write((int)(data_addr >> 8));
	Wire.write((int)(data_addr & 0xFF));
	Wire.write((int)b);
	Wire.endTransmission();
	delay(eeprom::WRITE_DELAY_MS);
}

	// Buttons grid for digit passwd
typedef uint8_t analog_pin_t;
typedef uint8_t digital_pin_t;
namespace bgrid {
	const digital_pin_t PIN_UP = 68; /*A14*/
	const int TRIGGERLVL_UP = 768; /* 75% 1024 */
	const digital_pin_t PIN_DOWN = 66; /*A12*/
	const int TRIGGERLVL_DOWN = 256; /* 25% 1024 */
	const uint8_t SZ = 3;
	const analog_pin_t PINS_UP [SZ] = { 10, 13, 15 };
	const analog_pin_t PINS_DOWN [SZ] = { 8, 11, 9 };
	const int DEFAULT_VALUE = -1;
	const int VALS [SZ][SZ] = {
		{ 1, 2, 3, },
		{ 4, 5, 6, },
		{ 7, 8, 9, },
	};
	void initGrid ();
	int getGridValue ();
}
void bgrid::initGrid () {
	pinMode(bgrid::PIN_UP, OUTPUT);
	digitalWrite(bgrid::PIN_UP, HIGH);
	pinMode(bgrid::PIN_DOWN, OUTPUT);
	digitalWrite(bgrid::PIN_DOWN, LOW);
}
int bgrid::getGridValue () {
	int cur_val = -1;
	while (true) {
		bool vals_up [bgrid::SZ];
		int8_t idx_up = -1;
		for (uint8_t i = 0; i < bgrid::SZ; i++) {
			vals_up[i] = (analogRead(bgrid::PINS_UP[i]) < bgrid::TRIGGERLVL_UP);
			if (vals_up[i]) idx_up = i;
		}
		bool vals_down [bgrid::SZ];
		int8_t idx_down = -1;
		for (uint8_t i = 0; i < bgrid::SZ; i++) {
			vals_down[i] = (analogRead(bgrid::PINS_DOWN[i]) > bgrid::TRIGGERLVL_DOWN);
			if (vals_down[i]) idx_down = i;
		}
		if (idx_up != -1 and idx_down != -1) {
			int val = bgrid::VALS[idx_up][idx_down];
			if (cur_val != -1 and cur_val != val)
				return cur_val;
			cur_val = val;
		} else {
			if (cur_val != -1)
				return cur_val;
		}
	}
}

	// Serial
byte serialRead () {
	while (!Serial.available());
	return Serial.read();
}

	// Leds / Buzzer
const digital_pin_t PIN_LED_RED = 15;
const digital_pin_t PIN_LED_GREEN = 16;

	// Main
void setup () {
	Serial.begin(9600);
	bgrid::initGrid();
	Wire.begin();
	pinMode(30, OUTPUT);
	digitalWrite(30, LOW);
	pinMode(PIN_LED_RED, OUTPUT);
	pinMode(PIN_LED_GREEN, OUTPUT);
	delay(100);
	Serial.write((byte)OK);
_reuse_conn:
	digitalWrite(PIN_LED_RED, HIGH);
	bool reuse = ::serialRead();
	arduino_auth_opcode op = (arduino_auth_opcode)::serialRead();

        /* TODO : CHECK PASSWD */

	digitalWrite(PIN_LED_RED, LOW);
	digitalWrite(PIN_LED_GREEN, HIGH);
	switch (op) {
		case OP_DUMP_EEPROM:
			Serial.write((byte)OK);
			for (size_t addr = 0; addr < eeprom::SZ; addr++) {
				if (addr % 32 == 0) {
					Serial.println();
					Serial.print(addr, HEX);
					Serial.print(" : ");
				}
				byte b = eeprom::i2c_eeprom_read_byte(eeprom::I2C_EEPROM_ADDR, addr);
				Serial.print((int)b, HEX);
				Serial.print(" ");
			}
			Serial.println(" ");
			if (reuse) goto _reuse_conn;
			else return;
		case OP_ERASE_EEPROM: 
			Serial.write((byte)OK);
			for (size_t addr = 0; addr < eeprom::SZ; addr++) 
				eeprom::i2c_eeprom_write_byte(eeprom::I2C_EEPROM_ADDR, addr, 0x0);
			Serial.write((byte)OK);
			if (reuse) goto _reuse_conn;
			else return;
		case OP_CHALLENGE: {
			Serial.write((byte)OK);
			uint8_t keyid_sz = ::serialRead();
			if (keyid_sz > KEY_ID_MAX_SZ) {
				Serial.write((byte)COMM_ERROR);
				return;
			}
			char* key_id = (char*)::malloc(keyid_sz);
			for (uint8_t i = 0; i < keyid_sz; i++) {
				key_id[i] = ::serialRead();
				if (key_id[i] == '\0') {
					Serial.write((byte)COMM_ERROR);
					return;
				}
			}
			uint8_t slot_key = -1;
			romaddr_t addr = eeprom::IDX_ADDR;
			bool match = true;
			uint8_t c = 0;
			while (true) {
				byte b = eeprom::i2c_eeprom_read_byte(eeprom::I2C_EEPROM_ADDR, addr);
				if (b == '\0') {
					if (c == 0) {
						Serial.write((byte)NOT_FOUND);
						return;
					}
					if (match == true) {
						b = eeprom::i2c_eeprom_read_byte(eeprom::I2C_EEPROM_ADDR, ++addr);
						slot_key = (uint8_t)b;
						break;
					} else {
						addr++;
						match = true;
						c = 0;
					}
				} else {
					if (match == true) {
						if (c >= keyid_sz) 
							match = false;
						else {
							if (key_id[c] != b) 
								match = false;
							else 
								c++;
						}
					}
				}
				addr++;
				if (addr >= eeprom::IDX_ADDR + eeprom::IDX_SZ) {
					Serial.write((byte)NOT_FOUND);
					return;
				}
			}
			romaddr_t addr_key =
				eeprom::KEYS_BEG + slot_key * KEY_SZ;
			if (slot_key >= eeprom::KEYS_NUM or addr_key + KEY_SZ > eeprom::SZ) {
				Serial.write((byte)EEPROM_ERROR);
				return;
			}
			::free(key_id);
			Serial.write((byte)OK);
			Serial.write((byte)slot_key);
				// WhirpoolHash(Challenge+Key)
			whirpool::ctx_t hashctx;
			whirpool::init(&hashctx);
			for (size_t i = 0; i < CHALLENGE_SZ; i++) {
				byte b = ::serialRead();
				whirpool::update(&hashctx, &b, 1);
			}
			for (size_t i = 0; i < KEY_SZ; i++) {
				byte b = eeprom::i2c_eeprom_read_byte(eeprom::I2C_EEPROM_ADDR, addr_key+i);
				whirpool::update(&hashctx, &b, 1);
			}
			whirpool::final(&hashctx);
			Serial.write((byte)OK);
			for (uint8_t i = 0; i < WHIRLPOOL_DIGEST_LENGTH; i++) 
				Serial.write(hashctx.H.c[i]);
			if (reuse) goto _reuse_conn;
			else return;
		}
		case OP_ADD_KEY: {
			Serial.write((byte)OK);
			uint8_t keyid_sz = ::serialRead();
			if (keyid_sz > KEY_ID_MAX_SZ) {
				Serial.write((byte)COMM_ERROR);
				return;
			}
			char* key_id = (char*)::malloc(keyid_sz);
			for (uint8_t i = 0; i < keyid_sz; i++) {
				key_id[i] = ::serialRead();
				if (key_id[i] == '\0') {
					Serial.write((byte)COMM_ERROR);
					return;
				}
			}
			uint8_t slot_newkey = 0x0;
			romaddr_t addr_idxentry;
			{
				romaddr_t addr = eeprom::IDX_ADDR;
				romaddr_t beg_entry_addr = addr;
				short used_keyslots [eeprom::KEYS_NUM];
				for (short i = 0; i < eeprom::KEYS_NUM; i++)
					used_keyslots[i] = -1;
				char currkeyid [KEY_ID_MAX_SZ + 1];
				currkeyid[0] = '\0';
				while (true) {
					byte b = eeprom::i2c_eeprom_read_byte(eeprom::I2C_EEPROM_ADDR, addr);
					if (b == '\0') {
						if (currkeyid[0] == '\0') {
							addr_idxentry = addr;
							if (addr_idxentry + keyid_sz + 3 >= eeprom::IDX_ADDR + eeprom::IDX_SZ) {
								Serial.write((byte)NO_MORE_SPACE);
								return;
							}
							for (short i = 0; ; i++) {
								if (i >= eeprom::KEYS_NUM) {
									Serial.write((byte)NO_MORE_SPACE);
									return;
								}
								if (used_keyslots[i] == -1)
									break;
								if (used_keyslots[i] >= slot_newkey)
									slot_newkey = used_keyslots[i] + 1;
							}
							if (slot_newkey >= eeprom::KEYS_NUM) {
								Serial.write((byte)NO_MORE_SPACE);
								return;
							}
							break;
						} else {
							bool found = false;
							for (uint8_t c = 0; ; c++) {
								if (c >= keyid_sz or currkeyid[c] == '\0') {
									found = (c = keyid_sz and currkeyid[c] == '\0');
									break;
								}
								if (key_id[c] != currkeyid[c]) 
									break;
							}
							currkeyid[0] = '\0';
							addr++;
							b = eeprom::i2c_eeprom_read_byte(eeprom::I2C_EEPROM_ADDR, addr);
							if (found) {
								slot_newkey = (short)b;
								addr_idxentry = beg_entry_addr;
								break;
							} else {
								for (uint8_t i = 0; ; i++) {
									if (i >= eeprom::KEYS_NUM) {
										Serial.write((byte)EEPROM_ERROR);
										return;
									}
									if (used_keyslots[i] == -1) {
										used_keyslots[i] = (short)b;
										break;
									}
								}
								beg_entry_addr = addr + 1;
							}
						}
					} else {
						for (uint8_t c = 0; ; c++) {
							if (c >= KEY_ID_MAX_SZ) {
								Serial.write((byte)EEPROM_ERROR);
								return;
							}
							if (currkeyid[c] == '\0') {
								currkeyid[c] = b;
								currkeyid[c + 1] = '\0';
								break;
							}
						}
					}
					addr++;
					if (addr >= eeprom::IDX_ADDR + eeprom::IDX_SZ) {
						Serial.write((byte)NO_MORE_SPACE);
						return;
					}
				}
			}
			romaddr_t addr_newkey =
			    eeprom::KEYS_BEG + slot_newkey * KEY_SZ;
			if (addr_newkey + KEY_SZ > eeprom::SZ) {
				Serial.write((byte)NO_MORE_SPACE);
				return;
			}
			Serial.write((byte)OK);
			Serial.write((byte)slot_newkey);
			for (short i = 0; i < KEY_SZ; i++) { /* warning : serial buffer is only 32; serial bus is faster than eeprom write => data can be discarded */
				byte b = ::serialRead();
				eeprom::i2c_eeprom_write_byte(eeprom::I2C_EEPROM_ADDR, addr_newkey + i, b);
			}
			Serial.write((byte)OK);
			for (uint8_t i = 0; i < keyid_sz; i++)
				eeprom::i2c_eeprom_write_byte(eeprom::I2C_EEPROM_ADDR, addr_idxentry + i, (byte)key_id[i]);
			eeprom::i2c_eeprom_write_byte(eeprom::I2C_EEPROM_ADDR, addr_idxentry + keyid_sz, (byte)'\0');
			eeprom::i2c_eeprom_write_byte(eeprom::I2C_EEPROM_ADDR, addr_idxentry + keyid_sz + 1, (byte)slot_newkey);
			Serial.write((byte)OK);
			if (reuse) goto _reuse_conn;
			else return;
		}
		default: 
			Serial.write((byte)COMM_ERROR);
			return;
	}
}

void loop () {
	delay(100);
	Serial.end();
	while (true);
}
