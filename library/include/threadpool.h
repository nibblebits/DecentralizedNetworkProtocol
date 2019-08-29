#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <functional>
#include <queue>
#include <thread>
#include <mutex>
#include "semaphore.h"

typedef std::function<void()> THREAD_FUNCTION;

namespace Dnp
{
struct thread_pool_task
{
    THREAD_FUNCTION task_func;
};

class ThreadPool
{

public:
    ThreadPool(int number_of_threads);
    virtual ~ThreadPool();

    void start();
    void addTask(THREAD_FUNCTION func);
    struct thread_pool_task getNextTask();

private:
    void thread_pool_run(int thread_id);

    int number_of_threads;
    std::vector<std::thread> threads;
    std::queue<struct thread_pool_task> tasks;
    std::mutex task_mutex;
    semaphore sem;
};
}; // namespace Dnp

#endif