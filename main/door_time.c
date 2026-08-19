#include "door_time.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include "esp_log.h"
#include "lwip/apps/sntp.h"

static const char *TAG = "door_time";

static bool leap_year(int year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static time_t build_timestamp(void)
{
    static const char *months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    static const int month_days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    char month_name[4] = {0};
    int day, year, hour, minute, second, month = -1;
    if (sscanf(__DATE__, "%3s %d %d", month_name, &day, &year) != 3 ||
        sscanf(__TIME__, "%d:%d:%d", &hour, &minute, &second) != 3) return 0;
    for (int i = 0; i < 12; ++i) if (!strcmp(month_name, months[i])) { month = i; break; }
    if (month < 0 || year < 2024 || day < 1 || day > month_days[month] + (month == 1 && leap_year(year))) return 0;

    int64_t days = 0;
    for (int y = 1970; y < year; ++y) days += leap_year(y) ? 366 : 365;
    for (int m = 0; m < month; ++m) days += month_days[m] + (m == 1 && leap_year(year));
    days += day - 1;
    return (time_t)(days * 86400 + hour * 3600 + minute * 60 + second);
}

bool door_time_ready(void)
{
    static bool started;
    time_t now;
    time(&now);
    if (!started) {
        sntp_setoperatingmode(SNTP_OPMODE_POLL);
        sntp_setservername(0, "pool.ntp.org");
        sntp_init();
        started = true;
    }
    if (now > 1704067200) return true; /* 2024-01-01 */

    time_t compiled = build_timestamp();
    if (compiled <= 1704067200) return false;
    struct timeval value = { .tv_sec = compiled, .tv_usec = 0 };
    if (settimeofday(&value, NULL) != 0) return false;
    ESP_LOGW(TAG, "SNTP unavailable; seeded clock from firmware build time until synchronization succeeds");
    return true;
}
