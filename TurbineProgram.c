#include <stdio.h>

int getCurrentRPM() 
{
    /*
    Code for getting current RPM
    */
    return 50;
}

void increaseRPM()
{
/* Code to increase RPM */
}

void decreaseRPM()
{
/* Code to decrease RPM */
}

int main()
{
    int MAX_RPM = 300;
    if(getCurrentRPM() > MAX_RPM)
    {
    	decreaseRPM();
    } else {
    	increaseRPM();
    }
}

