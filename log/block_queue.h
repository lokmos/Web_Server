#ifndef BLOCK_QUEUE_H
#define BLOCK_QUEUE_H

#include <iostream>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
#include "../lock/locker.h"
using namespace std;

template <typename T>
class block_queue {
public:
    block_queue(int max_size=1000) {
        if (max_size <= 0)
            exit(-1);
        
        m_array = new T[max_size];
        m_size = 0;
        m_max_size = max_size;
        m_front = -1;
        m_back = -1;
    }

    ~block_queue() {
        m_mutex.lock();
        delete []m_array;
        m_mutex.unlock();
    }

    void clear() {
        m_mutex.lock();
        m_size = 0;
        m_front = -1;
        m_back = -1;
        m_mutex.unlock();
    }

    bool full() {
        m_mutex.lock();
        if (m_size >= m_max_size) {
            m_mutex.unlock();
            return true;
        }
        m_mutex.unlock();
        return false;
    }

    bool empty() {
        m_mutex.lock();
        if (m_size == 0) {
            m_mutex.unlock();
            return true;
        }
        m_mutex.unlock();
        return false;
    }
    
private:
    locker m_mutex;
    cond m_cond;
    T *m_array;
    int m_size;
    int m_max_size;
    int m_front;
    int m_back;
};

#endif