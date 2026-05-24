#include "lib/packet.h"

typedef struct packet{
    struct tm timestamp;
    unsigned int size;
} Packet;