#ifndef DNPKERNELCLIENT_H
#define DNPKERNELCLIENT_H
#include <thread>
namespace Dnp
{
class DnpKernelClient
{
public:
    DnpKernelClient();
    virtual ~DnpKernelClient();

    virtual void start();
    virtual void run() = 0;
private:
    void start_thread();
    std::thread thread;
};
}; // namespace Dnp
#endif