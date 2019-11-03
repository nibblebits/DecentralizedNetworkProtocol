#ifndef DNPKERNELCLIENT_H
#define DNPKERNELCLIENT_H
#include <thread>

namespace Dnp
{
class System;
class DnpKernelClient
{
public:
    DnpKernelClient(System *system);
    virtual ~DnpKernelClient();

    virtual void start();
    virtual void run() = 0;

protected:
    System *system;
private:
    void start_thread();
    std::thread thread;
};
}; // namespace Dnp
#endif