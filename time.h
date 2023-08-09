#include <chrono>
#include <ctime>

#ifndef TIME_H_
#define TIME_H_

struct Time { 
    int hours;
    int minutes;

    bool operator <= (const Time& other) const {
        if (hours < other.hours) 
            return true;
        if (hours == other.hours)
            return minutes <= other.minutes;
        return false;
    }
};

#endif