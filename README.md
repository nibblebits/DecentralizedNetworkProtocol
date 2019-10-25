# DecentralizedNetworkProtocol
In development


DNP is a Decentralized Network Protocol that runs on Linux. Included is a kernel module which extends the standard Linux socket interface that you would send a UDP packet on. It is extended to allow for the DNP Network protocol to be used.

Sooner or later a decentralized network protocol will become a standard whilst I do not believe DNP will be it, I felt the need to create this project to demonstrate the power of a decentralized network protocol.

This project is still in development and is a prototype, upon completion you will be able to send DNP packets as you would send a UDP packet, however instead of providing an IP address you would provide a DNP address.

The packet is sent to the decentralized network and bounced around until it reaches your destination. 

# What is the power of this?

The power of a decentralized network means you can have an address associated to your computer or a program rather than an entire network. This means that you can move your Laptop from network to network but your address will stay the same, imagine having an ip address that follows you as you move this is what decentralization can provide.

Secondly a decentralized network allows you to require packets to be recieved, you could pass a socket option to the linux socket interface that asks DNP to require this packet to be recieved. If the host program listening on the port is offline or the laptop or machine is switched off then the packet will continue to be stored on the network until the recipient of the packet is back online where it is then sent to him.

These are just two examples of the power of decentralization
