#pragma once
#include "packet.h"

#define FIN_FLAG    0
#define RST_FLAG    1

#define FWD         0
#define BWD         1

bool send_block(const BYTE *data, BYTE flag, BYTE direction);