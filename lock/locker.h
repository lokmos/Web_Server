#ifndef LOCKER_H
#define LOCKER_H

#include <exception>
#include <pthread.h>
#include <semaphore.h>

// 封装信号量的类
class sem {
public:
    // 默认构造函数
    sem() {
        if (sem_init(&m_sem, 0, 0) != 0)
            throw std::exception();
    }

    // 初始化信号量
    sem(int num) {
        if (sem_init(&m_sem, 0, num) != 0)
            throw std::exception();
    }

    // 析构函数
    ~sem() {
        sem_destroy(&m_sem);
    }

    // 等待信号量
    bool wait() {
        return sem_wait(&m_sem) == 0;
    }

    // 增加信号量
    bool post() {
        return sem_post(&m_sem) == 0;
    }
private:
    sem_t m_sem;
};

// 封装互斥锁的类
class locker {
public:
    // 默认构造函数
    locker() {
        if (pthread_mutex_init(&m_mutex, NULL) != 0)
            throw std::exception();
    }

    // 析构函数
    ~locker() {
        pthread_mutex_destroy(&m_mutex);
    }

    // 上锁
    bool lock() {
        return pthread_mutex_lock(&m_mutex) == 0;
    }

    // 解锁
    bool unlock() {
        return pthread_mutex_unlock(&m_mutex) == 0;
    }

    // 获取互斥锁
    pthread_mutex_t *get() {
        return &m_mutex;
    }

private:
    pthread_mutex_t m_mutex;
};

// 封装条件变量的类
class cond {
public:
    // 默认构造函数
    cond() {
        if (pthread_cond_init(&m_cond, NULL) != 0)
            throw std::exception();
    }

    // 析构函数
    ~cond() {
        pthread_cond_destroy(&m_cond);
    }

    // 等待条件变量
    bool wait(pthread_mutex_t *m_mutex) {
        int ret = 0;
        pthread_mutex_lock(m_mutex);
        ret = pthread_cond_wait(&m_cond, m_mutex);
        pthread_mutex_unlock(m_mutex);
        return ret == 0;
    }

    // 超时等待条件变量
    bool timewait(pthread_mutex_t *m_mutex, struct timespec t) {
        int ret = 0;
        pthread_mutex_lock(m_mutex);
        ret = pthread_cond_timedwait(&m_cond, m_mutex, &t);
        pthread_mutex_unlock(m_mutex);
        return ret == 0;
    }

    // 唤醒等待条件变量的线程
    bool signal() {
        return pthread_cond_signal(&m_cond) == 0;
    }

    // 唤醒等待条件变量的所有线程
    bool broadcast() {
        return pthread_cond_broadcast(&m_cond) == 0;
    }
private:
    pthread_cond_t m_cond;
};

#endif