#include "threadpool.h"
#include <iostream>
#include <exception>
#include <unistd.h>

using namespace Dnp;
ThreadPool::ThreadPool(int number_of_threads)
{
    this->number_of_threads = number_of_threads;
}

ThreadPool::~ThreadPool()
{
    for (int i = 0; i < number_of_threads; i++)
    {
        this->threads[i].join();
    }
}

void ThreadPool::thread_pool_run(int thread_id)
{
    while (1)
    {
        // get next task is blocking so will wait and is thread safe
        struct thread_pool_task task = getNextTask();
        
        // Let's run this task!
        task.task_func();
    }
}
void ThreadPool::start()
{
    for (int i = 0; i < number_of_threads; i++)
    {
        this->threads.push_back(std::thread(&ThreadPool::thread_pool_run, this, i));
    }

}
void ThreadPool::addTask(THREAD_FUNCTION func)
{

    if (func == NULL)
    {
        throw std::logic_error("Provided function is NULL!");
    }

    struct thread_pool_task task;
    task.task_func = func;

    std::lock_guard<std::mutex> lock(this->task_mutex);
    this->tasks.push(task);
    sem.notify();
}

struct thread_pool_task ThreadPool::getNextTask()
{
    sem.wait();
    std::lock_guard<std::mutex> lock(this->task_mutex);
    struct thread_pool_task task = this->tasks.front();
    this->tasks.pop();
    return task;
}