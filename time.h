#include <chrono>
#include <ctime>
#include <iostream>
#include <sstream>
#include <iomanip>

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

    std::string to_string() const {
        std::ostringstream oss;

        oss << std::setfill('0') << std::setw(2) << hours << ":"
            << std::setfill('0') << std::setw(2) << minutes;

        return oss.str();
    }
};

#endif