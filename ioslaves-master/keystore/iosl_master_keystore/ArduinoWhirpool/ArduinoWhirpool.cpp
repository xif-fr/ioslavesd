#include "ArduinoWhirpool.h"

#include <avr/pgmspace.h>
#include <string.h>

namespace whirpool {
	
	const PROGMEM uint8_t Cx [256*sizeof(uint64_t)] = {
		0x18,0x18,0x60,0x18,0xc0,0x78,0x30,0xd8,
		0x23,0x23,0x8c,0x23,0x05,0xaf,0x46,0x26,
		0xc6,0xc6,0x3f,0xc6,0x7e,0xf9,0x91,0xb8,
		0xe8,0xe8,0x87,0xe8,0x13,0x6f,0xcd,0xfb,
		0x87,0x87,0x26,0x87,0x4c,0xa1,0x13,0xcb,
		0xb8,0xb8,0xda,0xb8,0xa9,0x62,0x6d,0x11,
		0x01,0x01,0x04,0x01,0x08,0x05,0x02,0x09,
		0x4f,0x4f,0x21,0x4f,0x42,0x6e,0x9e,0x0d,
		0x36,0x36,0xd8,0x36,0xad,0xee,0x6c,0x9b,
		0xa6,0xa6,0xa2,0xa6,0x59,0x04,0x51,0xff,
		0xd2,0xd2,0x6f,0xd2,0xde,0xbd,0xb9,0x0c,
		0xf5,0xf5,0xf3,0xf5,0xfb,0x06,0xf7,0x0e,
		0x79,0x79,0xf9,0x79,0xef,0x80,0xf2,0x96,
		0x6f,0x6f,0xa1,0x6f,0x5f,0xce,0xde,0x30,
		0x91,0x91,0x7e,0x91,0xfc,0xef,0x3f,0x6d,
		0x52,0x52,0x55,0x52,0xaa,0x07,0xa4,0xf8,
		0x60,0x60,0x9d,0x60,0x27,0xfd,0xc0,0x47,
		0xbc,0xbc,0xca,0xbc,0x89,0x76,0x65,0x35,
		0x9b,0x9b,0x56,0x9b,0xac,0xcd,0x2b,0x37,
		0x8e,0x8e,0x02,0x8e,0x04,0x8c,0x01,0x8a,
		0xa3,0xa3,0xb6,0xa3,0x71,0x15,0x5b,0xd2,
		0x0c,0x0c,0x30,0x0c,0x60,0x3c,0x18,0x6c,
		0x7b,0x7b,0xf1,0x7b,0xff,0x8a,0xf6,0x84,
		0x35,0x35,0xd4,0x35,0xb5,0xe1,0x6a,0x80,
		0x1d,0x1d,0x74,0x1d,0xe8,0x69,0x3a,0xf5,
		0xe0,0xe0,0xa7,0xe0,0x53,0x47,0xdd,0xb3,
		0xd7,0xd7,0x7b,0xd7,0xf6,0xac,0xb3,0x21,
		0xc2,0xc2,0x2f,0xc2,0x5e,0xed,0x99,0x9c,
		0x2e,0x2e,0xb8,0x2e,0x6d,0x96,0x5c,0x43,
		0x4b,0x4b,0x31,0x4b,0x62,0x7a,0x96,0x29,
		0xfe,0xfe,0xdf,0xfe,0xa3,0x21,0xe1,0x5d,
		0x57,0x57,0x41,0x57,0x82,0x16,0xae,0xd5,
		0x15,0x15,0x54,0x15,0xa8,0x41,0x2a,0xbd,
		0x77,0x77,0xc1,0x77,0x9f,0xb6,0xee,0xe8,
		0x37,0x37,0xdc,0x37,0xa5,0xeb,0x6e,0x92,
		0xe5,0xe5,0xb3,0xe5,0x7b,0x56,0xd7,0x9e,
		0x9f,0x9f,0x46,0x9f,0x8c,0xd9,0x23,0x13,
		0xf0,0xf0,0xe7,0xf0,0xd3,0x17,0xfd,0x23,
		0x4a,0x4a,0x35,0x4a,0x6a,0x7f,0x94,0x20,
		0xda,0xda,0x4f,0xda,0x9e,0x95,0xa9,0x44,
		0x58,0x58,0x7d,0x58,0xfa,0x25,0xb0,0xa2,
		0xc9,0xc9,0x03,0xc9,0x06,0xca,0x8f,0xcf,
		0x29,0x29,0xa4,0x29,0x55,0x8d,0x52,0x7c,
		0x0a,0x0a,0x28,0x0a,0x50,0x22,0x14,0x5a,
		0xb1,0xb1,0xfe,0xb1,0xe1,0x4f,0x7f,0x50,
		0xa0,0xa0,0xba,0xa0,0x69,0x1a,0x5d,0xc9,
		0x6b,0x6b,0xb1,0x6b,0x7f,0xda,0xd6,0x14,
		0x85,0x85,0x2e,0x85,0x5c,0xab,0x17,0xd9,
		0xbd,0xbd,0xce,0xbd,0x81,0x73,0x67,0x3c,
		0x5d,0x5d,0x69,0x5d,0xd2,0x34,0xba,0x8f,
		0x10,0x10,0x40,0x10,0x80,0x50,0x20,0x90,
		0xf4,0xf4,0xf7,0xf4,0xf3,0x03,0xf5,0x07,
		0xcb,0xcb,0x0b,0xcb,0x16,0xc0,0x8b,0xdd,
		0x3e,0x3e,0xf8,0x3e,0xed,0xc6,0x7c,0xd3,
		0x05,0x05,0x14,0x05,0x28,0x11,0x0a,0x2d,
		0x67,0x67,0x81,0x67,0x1f,0xe6,0xce,0x78,
		0xe4,0xe4,0xb7,0xe4,0x73,0x53,0xd5,0x97,
		0x27,0x27,0x9c,0x27,0x25,0xbb,0x4e,0x02,
		0x41,0x41,0x19,0x41,0x32,0x58,0x82,0x73,
		0x8b,0x8b,0x16,0x8b,0x2c,0x9d,0x0b,0xa7,
		0xa7,0xa7,0xa6,0xa7,0x51,0x01,0x53,0xf6,
		0x7d,0x7d,0xe9,0x7d,0xcf,0x94,0xfa,0xb2,
		0x95,0x95,0x6e,0x95,0xdc,0xfb,0x37,0x49,
		0xd8,0xd8,0x47,0xd8,0x8e,0x9f,0xad,0x56,
		0xfb,0xfb,0xcb,0xfb,0x8b,0x30,0xeb,0x70,
		0xee,0xee,0x9f,0xee,0x23,0x71,0xc1,0xcd,
		0x7c,0x7c,0xed,0x7c,0xc7,0x91,0xf8,0xbb,
		0x66,0x66,0x85,0x66,0x17,0xe3,0xcc,0x71,
		0xdd,0xdd,0x53,0xdd,0xa6,0x8e,0xa7,0x7b,
		0x17,0x17,0x5c,0x17,0xb8,0x4b,0x2e,0xaf,
		0x47,0x47,0x01,0x47,0x02,0x46,0x8e,0x45,
		0x9e,0x9e,0x42,0x9e,0x84,0xdc,0x21,0x1a,
		0xca,0xca,0x0f,0xca,0x1e,0xc5,0x89,0xd4,
		0x2d,0x2d,0xb4,0x2d,0x75,0x99,0x5a,0x58,
		0xbf,0xbf,0xc6,0xbf,0x91,0x79,0x63,0x2e,
		0x07,0x07,0x1c,0x07,0x38,0x1b,0x0e,0x3f,
		0xad,0xad,0x8e,0xad,0x01,0x23,0x47,0xac,
		0x5a,0x5a,0x75,0x5a,0xea,0x2f,0xb4,0xb0,
		0x83,0x83,0x36,0x83,0x6c,0xb5,0x1b,0xef,
		0x33,0x33,0xcc,0x33,0x85,0xff,0x66,0xb6,
		0x63,0x63,0x91,0x63,0x3f,0xf2,0xc6,0x5c,
		0x02,0x02,0x08,0x02,0x10,0x0a,0x04,0x12,
		0xaa,0xaa,0x92,0xaa,0x39,0x38,0x49,0x93,
		0x71,0x71,0xd9,0x71,0xaf,0xa8,0xe2,0xde,
		0xc8,0xc8,0x07,0xc8,0x0e,0xcf,0x8d,0xc6,
		0x19,0x19,0x64,0x19,0xc8,0x7d,0x32,0xd1,
		0x49,0x49,0x39,0x49,0x72,0x70,0x92,0x3b,
		0xd9,0xd9,0x43,0xd9,0x86,0x9a,0xaf,0x5f,
		0xf2,0xf2,0xef,0xf2,0xc3,0x1d,0xf9,0x31,
		0xe3,0xe3,0xab,0xe3,0x4b,0x48,0xdb,0xa8,
		0x5b,0x5b,0x71,0x5b,0xe2,0x2a,0xb6,0xb9,
		0x88,0x88,0x1a,0x88,0x34,0x92,0x0d,0xbc,
		0x9a,0x9a,0x52,0x9a,0xa4,0xc8,0x29,0x3e,
		0x26,0x26,0x98,0x26,0x2d,0xbe,0x4c,0x0b,
		0x32,0x32,0xc8,0x32,0x8d,0xfa,0x64,0xbf,
		0xb0,0xb0,0xfa,0xb0,0xe9,0x4a,0x7d,0x59,
		0xe9,0xe9,0x83,0xe9,0x1b,0x6a,0xcf,0xf2,
		0x0f,0x0f,0x3c,0x0f,0x78,0x33,0x1e,0x77,
		0xd5,0xd5,0x73,0xd5,0xe6,0xa6,0xb7,0x33,
		0x80,0x80,0x3a,0x80,0x74,0xba,0x1d,0xf4,
		0xbe,0xbe,0xc2,0xbe,0x99,0x7c,0x61,0x27,
		0xcd,0xcd,0x13,0xcd,0x26,0xde,0x87,0xeb,
		0x34,0x34,0xd0,0x34,0xbd,0xe4,0x68,0x89,
		0x48,0x48,0x3d,0x48,0x7a,0x75,0x90,0x32,
		0xff,0xff,0xdb,0xff,0xab,0x24,0xe3,0x54,
		0x7a,0x7a,0xf5,0x7a,0xf7,0x8f,0xf4,0x8d,
		0x90,0x90,0x7a,0x90,0xf4,0xea,0x3d,0x64,
		0x5f,0x5f,0x61,0x5f,0xc2,0x3e,0xbe,0x9d,
		0x20,0x20,0x80,0x20,0x1d,0xa0,0x40,0x3d,
		0x68,0x68,0xbd,0x68,0x67,0xd5,0xd0,0x0f,
		0x1a,0x1a,0x68,0x1a,0xd0,0x72,0x34,0xca,
		0xae,0xae,0x82,0xae,0x19,0x2c,0x41,0xb7,
		0xb4,0xb4,0xea,0xb4,0xc9,0x5e,0x75,0x7d,
		0x54,0x54,0x4d,0x54,0x9a,0x19,0xa8,0xce,
		0x93,0x93,0x76,0x93,0xec,0xe5,0x3b,0x7f,
		0x22,0x22,0x88,0x22,0x0d,0xaa,0x44,0x2f,
		0x64,0x64,0x8d,0x64,0x07,0xe9,0xc8,0x63,
		0xf1,0xf1,0xe3,0xf1,0xdb,0x12,0xff,0x2a,
		0x73,0x73,0xd1,0x73,0xbf,0xa2,0xe6,0xcc,
		0x12,0x12,0x48,0x12,0x90,0x5a,0x24,0x82,
		0x40,0x40,0x1d,0x40,0x3a,0x5d,0x80,0x7a,
		0x08,0x08,0x20,0x08,0x40,0x28,0x10,0x48,
		0xc3,0xc3,0x2b,0xc3,0x56,0xe8,0x9b,0x95,
		0xec,0xec,0x97,0xec,0x33,0x7b,0xc5,0xdf,
		0xdb,0xdb,0x4b,0xdb,0x96,0x90,0xab,0x4d,
		0xa1,0xa1,0xbe,0xa1,0x61,0x1f,0x5f,0xc0,
		0x8d,0x8d,0x0e,0x8d,0x1c,0x83,0x07,0x91,
		0x3d,0x3d,0xf4,0x3d,0xf5,0xc9,0x7a,0xc8,
		0x97,0x97,0x66,0x97,0xcc,0xf1,0x33,0x5b,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xcf,0xcf,0x1b,0xcf,0x36,0xd4,0x83,0xf9,
		0x2b,0x2b,0xac,0x2b,0x45,0x87,0x56,0x6e,
		0x76,0x76,0xc5,0x76,0x97,0xb3,0xec,0xe1,
		0x82,0x82,0x32,0x82,0x64,0xb0,0x19,0xe6,
		0xd6,0xd6,0x7f,0xd6,0xfe,0xa9,0xb1,0x28,
		0x1b,0x1b,0x6c,0x1b,0xd8,0x77,0x36,0xc3,
		0xb5,0xb5,0xee,0xb5,0xc1,0x5b,0x77,0x74,
		0xaf,0xaf,0x86,0xaf,0x11,0x29,0x43,0xbe,
		0x6a,0x6a,0xb5,0x6a,0x77,0xdf,0xd4,0x1d,
		0x50,0x50,0x5d,0x50,0xba,0x0d,0xa0,0xea,
		0x45,0x45,0x09,0x45,0x12,0x4c,0x8a,0x57,
		0xf3,0xf3,0xeb,0xf3,0xcb,0x18,0xfb,0x38,
		0x30,0x30,0xc0,0x30,0x9d,0xf0,0x60,0xad,
		0xef,0xef,0x9b,0xef,0x2b,0x74,0xc3,0xc4,
		0x3f,0x3f,0xfc,0x3f,0xe5,0xc3,0x7e,0xda,
		0x55,0x55,0x49,0x55,0x92,0x1c,0xaa,0xc7,
		0xa2,0xa2,0xb2,0xa2,0x79,0x10,0x59,0xdb,
		0xea,0xea,0x8f,0xea,0x03,0x65,0xc9,0xe9,
		0x65,0x65,0x89,0x65,0x0f,0xec,0xca,0x6a,
		0xba,0xba,0xd2,0xba,0xb9,0x68,0x69,0x03,
		0x2f,0x2f,0xbc,0x2f,0x65,0x93,0x5e,0x4a,
		0xc0,0xc0,0x27,0xc0,0x4e,0xe7,0x9d,0x8e,
		0xde,0xde,0x5f,0xde,0xbe,0x81,0xa1,0x60,
		0x1c,0x1c,0x70,0x1c,0xe0,0x6c,0x38,0xfc,
		0xfd,0xfd,0xd3,0xfd,0xbb,0x2e,0xe7,0x46,
		0x4d,0x4d,0x29,0x4d,0x52,0x64,0x9a,0x1f,
		0x92,0x92,0x72,0x92,0xe4,0xe0,0x39,0x76,
		0x75,0x75,0xc9,0x75,0x8f,0xbc,0xea,0xfa,
		0x06,0x06,0x18,0x06,0x30,0x1e,0x0c,0x36,
		0x8a,0x8a,0x12,0x8a,0x24,0x98,0x09,0xae,
		0xb2,0xb2,0xf2,0xb2,0xf9,0x40,0x79,0x4b,
		0xe6,0xe6,0xbf,0xe6,0x63,0x59,0xd1,0x85,
		0x0e,0x0e,0x38,0x0e,0x70,0x36,0x1c,0x7e,
		0x1f,0x1f,0x7c,0x1f,0xf8,0x63,0x3e,0xe7,
		0x62,0x62,0x95,0x62,0x37,0xf7,0xc4,0x55,
		0xd4,0xd4,0x77,0xd4,0xee,0xa3,0xb5,0x3a,
		0xa8,0xa8,0x9a,0xa8,0x29,0x32,0x4d,0x81,
		0x96,0x96,0x62,0x96,0xc4,0xf4,0x31,0x52,
		0xf9,0xf9,0xc3,0xf9,0x9b,0x3a,0xef,0x62,
		0xc5,0xc5,0x33,0xc5,0x66,0xf6,0x97,0xa3,
		0x25,0x25,0x94,0x25,0x35,0xb1,0x4a,0x10,
		0x59,0x59,0x79,0x59,0xf2,0x20,0xb2,0xab,
		0x84,0x84,0x2a,0x84,0x54,0xae,0x15,0xd0,
		0x72,0x72,0xd5,0x72,0xb7,0xa7,0xe4,0xc5,
		0x39,0x39,0xe4,0x39,0xd5,0xdd,0x72,0xec,
		0x4c,0x4c,0x2d,0x4c,0x5a,0x61,0x98,0x16,
		0x5e,0x5e,0x65,0x5e,0xca,0x3b,0xbc,0x94,
		0x78,0x78,0xfd,0x78,0xe7,0x85,0xf0,0x9f,
		0x38,0x38,0xe0,0x38,0xdd,0xd8,0x70,0xe5,
		0x8c,0x8c,0x0a,0x8c,0x14,0x86,0x05,0x98,
		0xd1,0xd1,0x63,0xd1,0xc6,0xb2,0xbf,0x17,
		0xa5,0xa5,0xae,0xa5,0x41,0x0b,0x57,0xe4,
		0xe2,0xe2,0xaf,0xe2,0x43,0x4d,0xd9,0xa1,
		0x61,0x61,0x99,0x61,0x2f,0xf8,0xc2,0x4e,
		0xb3,0xb3,0xf6,0xb3,0xf1,0x45,0x7b,0x42,
		0x21,0x21,0x84,0x21,0x15,0xa5,0x42,0x34,
		0x9c,0x9c,0x4a,0x9c,0x94,0xd6,0x25,0x08,
		0x1e,0x1e,0x78,0x1e,0xf0,0x66,0x3c,0xee,
		0x43,0x43,0x11,0x43,0x22,0x52,0x86,0x61,
		0xc7,0xc7,0x3b,0xc7,0x76,0xfc,0x93,0xb1,
		0xfc,0xfc,0xd7,0xfc,0xb3,0x2b,0xe5,0x4f,
		0x04,0x04,0x10,0x04,0x20,0x14,0x08,0x24,
		0x51,0x51,0x59,0x51,0xb2,0x08,0xa2,0xe3,
		0x99,0x99,0x5e,0x99,0xbc,0xc7,0x2f,0x25,
		0x6d,0x6d,0xa9,0x6d,0x4f,0xc4,0xda,0x22,
		0x0d,0x0d,0x34,0x0d,0x68,0x39,0x1a,0x65,
		0xfa,0xfa,0xcf,0xfa,0x83,0x35,0xe9,0x79,
		0xdf,0xdf,0x5b,0xdf,0xb6,0x84,0xa3,0x69,
		0x7e,0x7e,0xe5,0x7e,0xd7,0x9b,0xfc,0xa9,
		0x24,0x24,0x90,0x24,0x3d,0xb4,0x48,0x19,
		0x3b,0x3b,0xec,0x3b,0xc5,0xd7,0x76,0xfe,
		0xab,0xab,0x96,0xab,0x31,0x3d,0x4b,0x9a,
		0xce,0xce,0x1f,0xce,0x3e,0xd1,0x81,0xf0,
		0x11,0x11,0x44,0x11,0x88,0x55,0x22,0x99,
		0x8f,0x8f,0x06,0x8f,0x0c,0x89,0x03,0x83,
		0x4e,0x4e,0x25,0x4e,0x4a,0x6b,0x9c,0x04,
		0xb7,0xb7,0xe6,0xb7,0xd1,0x51,0x73,0x66,
		0xeb,0xeb,0x8b,0xeb,0x0b,0x60,0xcb,0xe0,
		0x3c,0x3c,0xf0,0x3c,0xfd,0xcc,0x78,0xc1,
		0x81,0x81,0x3e,0x81,0x7c,0xbf,0x1f,0xfd,
		0x94,0x94,0x6a,0x94,0xd4,0xfe,0x35,0x40,
		0xf7,0xf7,0xfb,0xf7,0xeb,0x0c,0xf3,0x1c,
		0xb9,0xb9,0xde,0xb9,0xa1,0x67,0x6f,0x18,
		0x13,0x13,0x4c,0x13,0x98,0x5f,0x26,0x8b,
		0x2c,0x2c,0xb0,0x2c,0x7d,0x9c,0x58,0x51,
		0xd3,0xd3,0x6b,0xd3,0xd6,0xb8,0xbb,0x05,
		0xe7,0xe7,0xbb,0xe7,0x6b,0x5c,0xd3,0x8c,
		0x6e,0x6e,0xa5,0x6e,0x57,0xcb,0xdc,0x39,
		0xc4,0xc4,0x37,0xc4,0x6e,0xf3,0x95,0xaa,
		0x03,0x03,0x0c,0x03,0x18,0x0f,0x06,0x1b,
		0x56,0x56,0x45,0x56,0x8a,0x13,0xac,0xdc,
		0x44,0x44,0x0d,0x44,0x1a,0x49,0x88,0x5e,
		0x7f,0x7f,0xe1,0x7f,0xdf,0x9e,0xfe,0xa0,
		0xa9,0xa9,0x9e,0xa9,0x21,0x37,0x4f,0x88,
		0x2a,0x2a,0xa8,0x2a,0x4d,0x82,0x54,0x67,
		0xbb,0xbb,0xd6,0xbb,0xb1,0x6d,0x6b,0x0a,
		0xc1,0xc1,0x23,0xc1,0x46,0xe2,0x9f,0x87,
		0x53,0x53,0x51,0x53,0xa2,0x02,0xa6,0xf1,
		0xdc,0xdc,0x57,0xdc,0xae,0x8b,0xa5,0x72,
		0x0b,0x0b,0x2c,0x0b,0x58,0x27,0x16,0x53,
		0x9d,0x9d,0x4e,0x9d,0x9c,0xd3,0x27,0x01,
		0x6c,0x6c,0xad,0x6c,0x47,0xc1,0xd8,0x2b,
		0x31,0x31,0xc4,0x31,0x95,0xf5,0x62,0xa4,
		0x74,0x74,0xcd,0x74,0x87,0xb9,0xe8,0xf3,
		0xf6,0xf6,0xff,0xf6,0xe3,0x09,0xf1,0x15,
		0x46,0x46,0x05,0x46,0x0a,0x43,0x8c,0x4c,
		0xac,0xac,0x8a,0xac,0x09,0x26,0x45,0xa5,
		0x89,0x89,0x1e,0x89,0x3c,0x97,0x0f,0xb5,
		0x14,0x14,0x50,0x14,0xa0,0x44,0x28,0xb4,
		0xe1,0xe1,0xa3,0xe1,0x5b,0x42,0xdf,0xba,
		0x16,0x16,0x58,0x16,0xb0,0x4e,0x2c,0xa6,
		0x3a,0x3a,0xe8,0x3a,0xcd,0xd2,0x74,0xf7,
		0x69,0x69,0xb9,0x69,0x6f,0xd0,0xd2,0x06,
		0x09,0x09,0x24,0x09,0x48,0x2d,0x12,0x41,
		0x70,0x70,0xdd,0x70,0xa7,0xad,0xe0,0xd7,
		0xb6,0xb6,0xe2,0xb6,0xd9,0x54,0x71,0x6f,
		0xd0,0xd0,0x67,0xd0,0xce,0xb7,0xbd,0x1e,
		0xed,0xed,0x93,0xed,0x3b,0x7e,0xc7,0xd6,
		0xcc,0xcc,0x17,0xcc,0x2e,0xdb,0x85,0xe2,
		0x42,0x42,0x15,0x42,0x2a,0x57,0x84,0x68,
		0x98,0x98,0x5a,0x98,0xb4,0xc2,0x2d,0x2c,
		0xa4,0xa4,0xaa,0xa4,0x49,0x0e,0x55,0xed,
		0x28,0x28,0xa0,0x28,0x5d,0x88,0x50,0x75,
		0x5c,0x5c,0x6d,0x5c,0xda,0x31,0xb8,0x86,
		0xf8,0xf8,0xc7,0xf8,0x93,0x3f,0xed,0x6b,
		0x86,0x86,0x22,0x86,0x44,0xa4,0x11,0xc2
	};
	
	static const union {
		uint8_t c [10*sizeof(uint64_t)];
		uint64_t q [10];
	} Rc = { {
		0x18,0x23,0xc6,0xe8,0x87,0xb8,0x01,0x4f,
		0x36,0xa6,0xd2,0xf5,0x79,0x6f,0x91,0x52,
		0x60,0xbc,0x9b,0x8e,0xa3,0x0c,0x7b,0x35,
		0x1d,0xe0,0xd7,0xc2,0x2e,0x4b,0xfe,0x57,
		0x15,0x77,0x37,0xe5,0x9f,0xf0,0x4a,0xda,
		0x58,0xc9,0x29,0x0a,0xb1,0xa0,0x6b,0x85,
		0xbd,0x5d,0x10,0xf4,0xcb,0x3e,0x05,0x67,
		0xe4,0x27,0x41,0x8b,0xa7,0x7d,0x95,0xd8,
		0xfb,0xee,0x7c,0x66,0xdd,0x17,0x47,0x9e,
		0xca,0x2d,0xbf,0x07,0xad,0x5a,0x83,0x33
	} };
	
	template <uint8_t N>
	inline uint64_t C (const union u64o& k, uint8_t i) {
        	uint16_t p = k.c[i*8+N]*8;
		uint64_t q = (uint64_t)pgm_read_dword_near(Cx+p) | (uint64_t)pgm_read_dword_near(Cx+p+4) << 32;
		return ( q << 8*N ^ q >> (8*(8-N)) );
	}
	template <>
	inline uint64_t C<0> (const union u64o& k, uint8_t i) {
        	uint16_t p = k.c[i*8]*8;
		uint64_t q = (uint64_t)pgm_read_dword_near(Cx+p) | (uint64_t)pgm_read_dword_near(Cx+p+4) << 32;
		return q;
	}
	
	void _update_block (struct whirpool::ctx_t*);
}

void whirpool::init (struct whirpool::ctx_t* ctx) {
	::memset(ctx, 0x0, sizeof(struct whirpool::ctx_t));
}

void whirpool::update (struct whirpool::ctx_t* ctx, const void* data, size_t bytes) {
	const uint8_t* p = (const uint8_t*)data;
	ctx->bitlen[0] += bytes*8;
	if (ctx->bitlen[0] < bytes*8) { // bitlen overflow
		size_t n = 1;
		do { ctx->bitlen[n]++; } while (ctx->bitlen[n] == 0 && ++n < WHIRLPOOL_COUNTER/sizeof(size_t));
	}
	while (bytes) {
		uint8_t b;
		b = p[0] | (p[1] >> 8);
		ctx->data[ctx->byteoff++] = b;
		bytes--;
		p++;
		if (ctx->byteoff >= WHIRLPOOL_BLOCK) {
			whirpool::_update_block(ctx);
			ctx->byteoff %= WHIRLPOOL_BLOCK;
		}
	}
}

void whirpool::final (struct whirpool::ctx_t* ctx) {
	ctx->data[ctx->byteoff++] = 0x80;
	if (ctx->byteoff > WHIRLPOOL_BLOCK - WHIRLPOOL_COUNTER) {
		if (ctx->byteoff < WHIRLPOOL_BLOCK)
			::memset(&ctx->data[ctx->byteoff], 0x0, WHIRLPOOL_BLOCK - ctx->byteoff);
		whirpool::_update_block(ctx);
		ctx->byteoff = 0;
	}
	else if (ctx->byteoff < WHIRLPOOL_BLOCK - WHIRLPOOL_COUNTER)
		::memset(&ctx->data[ctx->byteoff], 0x0, WHIRLPOOL_BLOCK - WHIRLPOOL_COUNTER - ctx->byteoff);
	uint8_t* p = &ctx->data[WHIRLPOOL_BLOCK-1];
	for (size_t i = 0; i < WHIRLPOOL_COUNTER/sizeof(size_t); i++) 
		for (size_t j=0, v = ctx->bitlen[i]; j < sizeof(size_t); j++, v>>=8) 
			*p-- = (uint8_t)(v & 0xff);
	whirpool::_update_block(ctx);
}

void whirpool::_update_block (struct whirpool::ctx_t* ctx) {
	const uint64_t* pq = (const uint64_t*)ctx->data;
	union u64o S, K;
	uint64_t L0, L1, L2, L3, L4, L5, L6, L7;
	S.q[0] = (K.q[0] = ctx->H.q[0]) ^ pq[0];
	S.q[1] = (K.q[1] = ctx->H.q[1]) ^ pq[1];
	S.q[2] = (K.q[2] = ctx->H.q[2]) ^ pq[2];
	S.q[3] = (K.q[3] = ctx->H.q[3]) ^ pq[3];
	S.q[4] = (K.q[4] = ctx->H.q[4]) ^ pq[4];
	S.q[5] = (K.q[5] = ctx->H.q[5]) ^ pq[5];
	S.q[6] = (K.q[6] = ctx->H.q[6]) ^ pq[6];
	S.q[7] = (K.q[7] = ctx->H.q[7]) ^ pq[7];
	for (uint8_t r = 0; r < 10; r++) {
		L0 = C<0>(K,0) ^ C<1>(K,7) ^ C<2>(K,6) ^ C<3>(K,5) ^ C<4>(K,4) ^ C<5>(K,3) ^ C<6>(K,2) ^ C<7>(K,1) ^ Rc.q[r];
		L1 = C<0>(K,1) ^ C<1>(K,0) ^ C<2>(K,7) ^ C<3>(K,6) ^ C<4>(K,5) ^ C<5>(K,4) ^ C<6>(K,3) ^ C<7>(K,2);
		L2 = C<0>(K,2) ^ C<1>(K,1) ^ C<2>(K,0) ^ C<3>(K,7) ^ C<4>(K,6) ^ C<5>(K,5) ^ C<6>(K,4) ^ C<7>(K,3);
		L3 = C<0>(K,3) ^ C<1>(K,2) ^ C<2>(K,1) ^ C<3>(K,0) ^ C<4>(K,7) ^ C<5>(K,6) ^ C<6>(K,5) ^ C<7>(K,4);
		L4 = C<0>(K,4) ^ C<1>(K,3) ^ C<2>(K,2) ^ C<3>(K,1) ^ C<4>(K,0) ^ C<5>(K,7) ^ C<6>(K,6) ^ C<7>(K,5);
		L5 = C<0>(K,5) ^ C<1>(K,4) ^ C<2>(K,3) ^ C<3>(K,2) ^ C<4>(K,1) ^ C<5>(K,0) ^ C<6>(K,7) ^ C<7>(K,6);
		L6 = C<0>(K,6) ^ C<1>(K,5) ^ C<2>(K,4) ^ C<3>(K,3) ^ C<4>(K,2) ^ C<5>(K,1) ^ C<6>(K,0) ^ C<7>(K,7);
		L7 = C<0>(K,7) ^ C<1>(K,6) ^ C<2>(K,5) ^ C<3>(K,4) ^ C<4>(K,3) ^ C<5>(K,2) ^ C<6>(K,1) ^ C<7>(K,0);
		K.q[0] = L0; K.q[1] = L1; K.q[2] = L2; K.q[3] = L3; K.q[4] = L4; K.q[5] = L5; K.q[6] = L6; K.q[7] = L7;
		L0 ^= C<0>(S,0) ^ C<1>(S,7) ^ C<2>(S,6) ^ C<3>(S,5) ^ C<4>(S,4) ^ C<5>(S,3) ^ C<6>(S,2) ^ C<7>(S,1);
		L1 ^= C<0>(S,1) ^ C<1>(S,0) ^ C<2>(S,7) ^ C<3>(S,6) ^ C<4>(S,5) ^ C<5>(S,4) ^ C<6>(S,3) ^ C<7>(S,2);
		L2 ^= C<0>(S,2) ^ C<1>(S,1) ^ C<2>(S,0) ^ C<3>(S,7) ^ C<4>(S,6) ^ C<5>(S,5) ^ C<6>(S,4) ^ C<7>(S,3);
		L3 ^= C<0>(S,3) ^ C<1>(S,2) ^ C<2>(S,1) ^ C<3>(S,0) ^ C<4>(S,7) ^ C<5>(S,6) ^ C<6>(S,5) ^ C<7>(S,4);
		L4 ^= C<0>(S,4) ^ C<1>(S,3) ^ C<2>(S,2) ^ C<3>(S,1) ^ C<4>(S,0) ^ C<5>(S,7) ^ C<6>(S,6) ^ C<7>(S,5);
		L5 ^= C<0>(S,5) ^ C<1>(S,4) ^ C<2>(S,3) ^ C<3>(S,2) ^ C<4>(S,1) ^ C<5>(S,0) ^ C<6>(S,7) ^ C<7>(S,6);
		L6 ^= C<0>(S,6) ^ C<1>(S,5) ^ C<2>(S,4) ^ C<3>(S,3) ^ C<4>(S,2) ^ C<5>(S,1) ^ C<6>(S,0) ^ C<7>(S,7);
		L7 ^= C<0>(S,7) ^ C<1>(S,6) ^ C<2>(S,5) ^ C<3>(S,4) ^ C<4>(S,3) ^ C<5>(S,2) ^ C<6>(S,1) ^ C<7>(S,0);
		S.q[0] = L0; S.q[1] = L1; S.q[2] = L2; S.q[3] = L3; S.q[4] = L4; S.q[5] = L5; S.q[6] = L6; S.q[7] = L7;
	}
	ctx->H.q[0] ^= S.q[0] ^ pq[0];
	ctx->H.q[1] ^= S.q[1] ^ pq[1];
	ctx->H.q[2] ^= S.q[2] ^ pq[2];
	ctx->H.q[3] ^= S.q[3] ^ pq[3];
	ctx->H.q[4] ^= S.q[4] ^ pq[4];
	ctx->H.q[5] ^= S.q[5] ^ pq[5];
	ctx->H.q[6] ^= S.q[6] ^ pq[6];
	ctx->H.q[7] ^= S.q[7] ^ pq[7];
}