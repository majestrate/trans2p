# trans2p

i2p ip proxy thingydoo with built in dns resolver doohicky and assorted other crap.

requirements:

* c11 compiler
* c++ 17 compiler (for now)
* libssl (libressl or openssl)
* cmake

platforms:

* linux x86-64/arm/ppc
* freebsd x86-64/arm
* netbsd x86-64
* windows x64-64 (eventually)

building:

    $ mkdir build 
    $ cmake ..
    $ make

using:

    ¯\(._.)/¯

status:

it sorta does stuff but not really, it'll get done eventually.

    ~psi    only needs a libssl
    ~psi    everything else is included
    ~psi    no boost
    ~psi    uses epoll/kqueue
    ~psi    kqueue coming soon
    ~psi    if someone wants to add kqueue let me know
    ~psi    you'll love the readme
    ~psi    ideally i'd like to get rid of the libssl requirement
    ~psi    but i am using i2pd's crypto code so i can get shit done
    ~psi    eventually i'll remove the c++ parts
    ~psi    and replace it with C 
    ~psi    the general idea of this is that it makes a tun interface that translates between tcp/ip and i2p streaming
    ~psi    and does udp
    ~psi    and it's all via i2cp
    ~psi    and it will be able to do inbound traffic too
    anabolic        i wasnt aware there was a difference
    ~psi    there are slight differences that make me go crazy
    ~psi    i2p streaming has no handshake
    ~psi    tcp does
    ~psi    so want i want to do is do a full tcp handshake and then attempt to connect via i2p streaming
    ~psi    then reset if there is no response or there is a timeout
    ~psi    if it's done that way then you can take advantage of i2p's streaming stuff
    ~psi    like bundling a segment in the streaming open packet
    ~psi    includes a dns resolver too that maps b32 to ip
    ~psi    and back
    ~psi    so a ptr lookup for the ip returns a b32.i2p address
    ~psi    the general usecase of this is you set your dns to use the ip address of the interface created
    ~psi    then it'll magically just work
    ~psi    automap i2p and maybe onions
    ~psi    autoproxy everything
    ~psi    inbound and outbound connections
    
