#pragma once

#include <stdbool.h>

/* Starts SNTP and guarantees a TLS-usable lower-bound time from the build. */
bool door_time_ready(void);
