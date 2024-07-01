# 5 Linux网络编程基础API

## 5.1 socket地址API

### 5.1.1 主机字节序和网络字节序

字节序分为大端字节序（big endian）和小端字节序（little endian）。

- 大端字节序是指一个整数的高位字节（23～31 bit）存储在内存的低地址处，低位字节（0～7 bit）存储在内存的高地址处
- 小端字节序则是指整数的高位字节存储在内存的高地址处，而低位字节则存储在内存的低地址处

小端字节序又被称为**主机字节序**

- 因为现代PC大多采用小端字节序

大端字节序又被称为**网络字节序**

- 它给所有接收数据的主机提供了一个正确解释收到的格式化数据的保证
- 当格式化的数据在两台使用不同字节序的主机之间直接传递时，接收端必然错误地解释之
  - 解决问题的方法是：发送端总是把要发送的数据转化成**大端字节序**数据后再发送，而接收端知道对方传送过来的数据总是采用大端字节序，所以接收端可以根据自身采用的字节序决定是否对接收到的数据进行转换

需要指出的是，即使是同一台机器上的两个进程（比如一个由C语言编写，另一个由JAVA编写）通信，也要考虑字节序的问题（JAVA虚拟机采用大端字节序）

Linux提供了如下四个函数来完成主机字节序和网络字节序之间的转换：

- ```c
  #include＜netinet/in.h＞
  unsigned long int htonl(unsigned long int hostlong);
  unsigned short int htons(unsigned short int hostshort);
  unsigned long int ntohl(unsigned long int netlong);
  unsigned short int ntohs(unsigned short int netshort);
  ```

- 它们的含义很明确，比如htonl表示“host to network long”，即将长
  整型（32 bit）的主机字节序数据转化为网络字节序数据。



### 5.1.2 通用socket地址

socket网络编程接口中表示socket地址的是结构体sockaddr，其定义如下：

- ```c
  #include＜bits/socket.h＞
  struct sockaddr
  {
      sa_family_t sa_family;
      char sa_data[14];
  }
  ```

  - sa_family成员是地址族类型（sa_family_t）的变量。地址族类型通常与协议族类型对应。常见的协议族（protocol family，也称domain，见后文）和对应的地址族如表5-1所示

    - | 协议族   | 地址族   | 描述              |
      | -------- | -------- | ----------------- |
      | PF_UNIX  | AF_UNIX  | UNIX 本地域协议族 |
      | PF_INET  | AF_INET  | TCP/IPv4 协议族   |
      | PF_INET6 | AF_INET6 | TCP/IPv6 协议族   |

    - 宏PF_\*和AF_\*都定义在bits/socket.h头文件中，且后者与前者有完全相同的值，所以二者通常混用。

  - sa_data存放socket地址

    - | 协议族   | 地址值含义和长度                                             |
      | -------- | ------------------------------------------------------------ |
      | PF_UNIX  | 文件的路径名，长度可达到 108 字节（见后文）                  |
      | PF_INET  | 16 bit 端口号和 32 bit IPv4 地址；共 6 字节                  |
      | PF_INET6 | 16 bit 端口号，32 bit 流标识，128 bit IPv6 地址；32 bit 范围 ID，共 26 字节 |

- 上述结构体的 sa_data 只有14字节，无法容纳多数协议族的地址，为此，Linux定义了如下的新的通用socket地址结构：

  - ```c
    #include＜bits/socket.h＞
    struct sockaddr_storage
    {
        sa_family_t sa_family;
        unsigned long int__ss_align;
        char__ss_padding[128-sizeof(__ss_align)];
    }
    ```

    - 提供了足够大的空间
    - 且是内存对齐的 （通过__ss_align实现）



### 5.1.3 专用socket地址

通用地址使用不方便（eg.获取端口和地址需要位操作），Linux为各协议族提供了专用的socket地址结构

**UNIX**

```c
#include＜sys/un.h＞
struct sockaddr_un
{
    sa_family_t sin_family;/*地址族：AF_UNIX*/
    char sun_path[108];/*文件路径名*/
};
```

**TCP**

有两个，分别用于 IPv4 和 IPv6

```c
struct sockaddr_in
{
    sa_family_t sin_family;/*地址族：AF_INET*/
    u_int16_t sin_port;/*端口号，要用网络字节序表示*/
    struct in_addr sin_addr;/*IPv4地址结构体，见下面*/
};
struct in_addr
{
    u_int32_t s_addr;/*IPv4地址，要用网络字节序表示*/
};
struct sockaddr_in6
{
    sa_family_t sin6_family;/*地址族：AF_INET6*/
    u_int16_t sin6_port;/*端口号，要用网络字节序表示*/
    u_int32_t sin6_flowinfo;/*流信息，应设置为0*/
    struct in6_addr sin6_addr;/*IPv6地址结构体，见下面*/
    u_int32_t sin6_scope_id;/*scope ID，尚处于实验阶段*/
};
struct in6_addr
{
    unsigned char sa_addr[16];/*IPv6地址，要用网络字节序表示*/
};
```

所有专用socket地址（以及sockaddr_storage）类型的变量在实际使用时都需要转化为通用socket地址类型sockaddr（强制转换即可），因为所有socket编程接口使用的地址参数的类型都是sockaddr。



#### 5.1.4 IP地址转换函数

**IPv4**

```c
#include＜arpa/inet.h＞
in_addr_t inet_addr(const char*strptr);
int inet_aton(const char*cp,struct in_addr*inp);
char*inet_ntoa(struct in_addr in);
```

- inet_addr函数将用点分十进制字符串表示的IPv4地址转化为用网络字节序整数表示的IPv4地址。它失败时返回INADDR_NONE

- inet_aton函数完成和inet_addr同样的功能，但是将转化结果存储于参数inp指向的地址结构中。它成功时返回1，失败则返回0

- inet_ntoa函数将用网络字节序整数表示的IPv4地址转化为用点分十进制字符串表示的IPv4地址

  - 内部用一个静态变量存储转化结果

  - 返回指向该变量的指针

  - 不可重用

    - ```c
      char* szValue1 = inet_ntoa("1.2.3.4");
      char* szValue2 = inet_ntoa("10.194.71.60");
      printf("address 1:%s\n", szValue1);
      printf("address 2:%s\n", szValue2);
      ```

    - `inet_ntoa` 使用了静态缓冲区来存储结果字符串。这意味着每次调用该函数时，返回的字符串指针都指向相同的静态内存区域。新调用将覆盖之前的结果

    - ```
      address 1:10.194.71.60
      address 2:10.194.71.60
      ```

**IPv6**

下面两个函数同时适用于 IPv4 和 IPv6

```c
#include＜arpa/inet.h＞
int inet_pton(int af,const char*src,void*dst);
const char*inet_ntop(int af,const void*src,char*dst,socklen_t cnt);
```

- inet_pton函数将用字符串表示的IP地址src（用点分十进制字符串表示的IPv4地址或用十六进制字符串表示的IPv6地址）转换成用网络字节序整数表示的IP地址，并把转换结果存储于dst指向的内存中

  - af参数指定地址族，可以是AF_INET或者AF_INET6
  - 成功时返回1，失败则返回0并设置errno

- inet_ntop函数进行相反的转换，前三个参数的含义与inet_pton的参数相同，最后一个参数cnt指定目标存储单元的大小（用下面的两个宏）

  - ```c
    #include＜netinet/in.h＞
    #define INET_ADDRSTRLEN 16
    #define INET6_ADDRSTRLEN 46
    ```

  - 成功时返回目标存储单元的地址，失败则返回NULL并设置errno



## 5.2 创建socket

UNIX/Linux的一个哲学是：所有东西都是文件。socket也不例外，它就是可读、可写、可控制、可关闭的文件描述符。下面的socket系统调用可创建一个socket：

```c
#include＜sys/types.h＞
#include＜sys/socket.h＞
int socket(int domain,int type,int protocol);
```

- domain参数告诉系统使用哪个底层协议族。
  - 对TCP/IP协议族而言，该参数应该设置为PF_INET（Protocol Family of Internet，用于IPv4）或PF_INET6（用于IPv6）；
  - 对于UNIX本地域协议族而言，该参数应该设置为PF_UNIX。
- type参数指定服务类型。
  - 指定传输协议
    - 取SOCK_STREAM表示传输层使用TCP协议，
    - 取SOCK_DGRAM表示传输层使用UDP协议。
  - 指定重要标志
    - SOCK_NONBLOCK 表示非阻塞
    - SOCK_CLOEXEC 表示用fork创建子进程时，在**子进程**中关闭该socket
  - type 取以上两者的与&
- protocol参数是在前两个参数构成的协议集合下，再选择一个具体的协议。不过这个值通常都是唯一的（前两个参数已经完全决定了它的值）。几乎在所有情况下，我们都应该把它设置为0，表示使用默认协议
- 成功时返回一个socket文件描述符，失败则返回-1并设置errno



## 5.3 命名socket

将一个socket与socket地址绑定称为给socket命名，在服务端通常要命名socket，只有这样客户端才能知道如何连接它；在客户端通常不需要命名，采用匿名方式，使用操作系统紫铜分配的socket地址

命名socket的系统调用是**bind**

```c
#include＜sys/types.h＞
#include＜sys/socket.h＞
int bind(int sockfd,const struct sockaddr*my_addr,socklen_t
addrlen);
```

- bind将my_addr所指的socket地址分配给未命名的sockfd文件描述符，addrlen参数指出该socket地址的长度
- 成功时返回0，失败则返回-1并设置errno
  - EACCES，被绑定的地址是受保护的地址，仅超级用户能够访问
    - 比如普通用户将socket绑定到知名服务端口（端口号为0～1023）上时
  - EADDRINUSE，被绑定的地址正在使用中
    - 比如将socket绑定到一个处于TIME_WAIT状态的socket地址



## 5.4 监听socket

socket被命名之后，还不能马上接受客户连接，我们需要使用如下系统调用来创建一个监听队列以存放待处理的客户连接：

```c
#include＜sys/socket.h＞
int listen(int sockfd,int backlog);
```

- sockfd参数指定被监听的socket
- backlog参数提示内核监听队列的最大长度
  - 监听队列的长度如果超过backlog，服务器将不受理新的客户连接，客户端也将收到ECONNREFUSED错误信息
  - 在内核版本2.2之前的Linux中，backlog参数是指所有处于半连接状态（SYN_RCVD）和完全连接状态（ESTABLISHED）的socket的上限
  - 自内核版本2.2之后，它只表示处于完全连接状态的socket的上限，处于半连接状态的socket的上限则
    由/proc/sys/net/ipv4/tcp_max_syn_backlog内核参数定义。
  - backlog参数的典型值是5
- 成功时返回0，失败则返回-1并设置errno

在实际中，监听队列中完整连接的上限通常比backlog值略大



## 5.5 接受连接

下面的系统调用从listen监听队列中接受一个连接：

```c
#include＜sys/types.h＞
#include＜sys/socket.h＞
int accept(int sockfd,struct sockaddr*addr,socklen_t*addrlen);
```

- sockfd参数是**执行过listen系统调用的监听socket**
- addr参数用来获取被接受连接的远端socket地址，该socket地址的长度由addrlen参数指出
- 成功时返回一个新的连接socket，该socket**唯一地标识了被接受的这个连接**，服务器可通过读写该socket来与被接受连接对应的客户端通信。accept失败时返回-1并设置errno

accept 只是从监听队列中取出连接，**不论连接处于何种状态**，更不关心任何网络状况的变化（即使客户端已经断线）



## 5.6 发起连接

客户端通过如下系统调用来**主动**与服务器建立连接

```c
#include＜sys/types.h＞
#include＜sys/socket.h＞
int connect(int sockfd,const struct sockaddr*serv_addr,socklen_t addrlen);
```

- sockfd参数由socket系统调用返回一个socket。serv_addr参数是服务器监听的socket地址，addrlen参数则指定这个地址的长度。

- 成功返回0。一旦成功建立连接，sockfd就唯一地标识了这个连接，客户端就可以通过读写sockfd来与服务器通信
- 失败则返回-1并设置errno
  - ECONNREFUSED，目标端口不存在，连接被拒绝
  - ETIMEDOUT，连接超时



## 5.7 关闭连接

关闭一个连接实际上就是关闭该连接对应的socket，这可以通过如下关闭普通文件描述符的系统调用来完成：

```c
#include＜unistd.h＞
int close(int fd);
```

- fd参数是待关闭的socket。不过，close系统调用并非总是立即关闭一个连接，而是将fd的引用计数减1。只有当fd的引用计数为0时，才真正关闭连接。多进程程序中，一次fork系统调用默认将使父进程中打开的socket的引用计数加1，因此我们必须在父进程和子进程中都对该socket执行close调用才能将连接关闭。

**shutdown**是专门为网络编程设计的**立即终止连接**的系统调用

```c
#include＜sys/socket.h＞
int shutdown(int sockfd,int howto);
```

- sockfd参数是待关闭的socket

- howto参数决定了shutdown的行为

  - | 可选值    | 含义                                                         |
    | --------- | ------------------------------------------------------------ |
    | SHUT_RD   | 关闭 `sockfd` 上读的这一半。应用程序不能再针对 `socket` 文件描述符执行读操作，并且该 `socket` 接收缓冲区中的数据都被丢弃。 |
    | SHUT_WR   | 关闭 `sockfd` 上写的这一半。`sockfd` 的发送缓冲区中的数据会在真正关闭连接之前全部发出去。应用程序不可再对该 `socket` 文件描述符执行写操作。这种情况下，连接处于半关闭状态。 |
    | SHUT_RDWR | 同时关闭 `sockfd` 上的读和写。                               |

- 成功时返回0，失败返回-1并设置errno



## 5.8 数据读写

### 5.8.1 TCP数据读写

```c
#include＜sys/types.h＞
#include＜sys/socket.h＞
ssize_t recv(int sockfd,void*buf,size_t len,int flags);
ssize_t send(int sockfd,const void*buf,size_t len,int flags);
```

- recv读取sockfd上的数据，buf和len参数分别指定读缓冲区的位置和大小，flags参数的含义见后文，通常设置为0即可
  - recv成功时返回实际读取到的数据的长度，它可能小于我们期望的长度len。因此我们可能要多次调用recv，才能读取到完整的数据
  - recv可能返回0，这意味着通信对方已经关闭连接了
  - recv出错时返回-1并设置errno
- send往sockfd上写入数据，buf和len参数分别指定写缓冲区的位置
  和大小。
  - send成功时返回实际写入的数据的长度，
  - 失败则返回-1并设置errno



### 5.8.2 UDP数据读写

```c
#include＜sys/types.h＞
#include＜sys/socket.h＞
ssize_t recvfrom(int sockfd,void*buf,size_t len,int flags,struct sockaddr*src_addr,socklen_t*addrlen);
ssize_t sendto(int sockfd,const void*buf,size_t len,int flags,const struct sockaddr*dest_addr,socklen_t addrlen);
```

- recvfrom读取sockfd上的数据，buf和len参数分别指定读缓冲区的位置和大小。因为UDP通信没有连接的概念，所以我们每次读取数据都需要获取发送端的socket地址，即参数src_addr所指的内容，addrlen参数则指定该地址的长度
- sendto往sockfd上写入数据，buf和len参数分别指定写缓冲区的位置和大小。dest_addr参数指定接收端的socket地址，addrlen参数则指定该地址的长度
- 这两个函数也可以用于面向连接（字节流）的socket的数据读写，只需要把最后两个参数设置为NULL来忽略发送/接收端的socket地址



### 5.8.3 通用数据读写

socket编程接口还提供了一对通用的数据读写系统调用。它们不仅能用于TCP流数据，也能用于UDP数据报：

```c
#include＜sys/socket.h＞
ssize_t recvmsg(int sockfd,struct msghdr*msg,int flags);
ssize_t sendmsg(int sockfd,struct msghdr*msg,int flags);
```

- msg参数是msghdr结构体类型的指针，msghdr结构体的定义如下：

  - ```c
    	struct msghdr
    {
        void*msg_name;/*socket地址*，对于TCP，设置为NULL/
        socklen_t msg_namelen;/*socket地址的长度*/
        struct iovec*msg_iov;/*分散的内存块，见后文*/
        int msg_iovlen;/*分散内存块的数量*/
        void*msg_control;/*指向辅助数据的起始位置*/
        socklen_t msg_controllen;/*辅助数据的大小*/
        int msg_flags;/*复制函数中的flags参数，并在调用过程中更新*/
    };
    ```

  - msg_iov成员是iovec结构体类型的指针，iovec结构体的定义如下：

    - ```c
      struct iovec
      {
          void*iov_base;/*内存起始地址*/
          size_t iov_len;/*这块内存的长度*/
      };
      ```

    - 对于recvmsg，数据将被读取并存放在msg_iovlen块分散的内存中，这些内存的位置和长度则由msg_iov指向的数组指定，这称为分散读（scatter read）

    - 对于sendmsg而言，msg_iovlen块分散内存中的数据将被一并发送，这称为集中写（gather write）

- msg_flags成员无须设定，它会复制recvmsg/sendmsg的flags参数的内容以影响数据读写过程。recvmsg还会在调用结束前，将某些更新后的标志设置到msg_flags中



## 5.9 带外标记

```c
#include＜sys/socket.h＞
int sockatmark(int sockfd);
```

- sockatmark判断sockfd是否处于带外标记，即下一个被读取到的数
  据是否是带外数据。
  - 如果是，sockatmark返回1，此时我们就可以利用带MSG_OOB标志的recv调用来接收带外数据。
  - 如果不是，则sockatmark返回0



## 5.10 地址信息函数

获取一个连接socket的本端socket地址/远端socket地址

```c
#include＜sys/socket.h＞
int getsockname(int sockfd,struct sockaddr*address,socklen_t*address_len);
int getpeername(int sockfd,struct
sockaddr*address,socklen_t*address_len);
```

- getsockname获取sockfd对应的本端socket地址，并将其存储于address参数指定的内存中，该socket地址的长度则存储于address_len参数指向的变量中
  - 如果实际socket地址的长度大于address所指内存区的大小，那么该socket地址将被截断
  - getsockname成功时返回0，失败返回-1并设置errno
- getpeername获取sockfd对应的远端socket地址，其参数及返回值的含义与getsockname的参数及返回值相同



## 5.11 socket选项

```c
#include＜sys/socket.h＞
int getsockopt(int sockfd,int level,int option_name,void*option_value,socklen_t*restrict option_len);
int setsockopt(int sockfd,int level,int option_name,const void*option_value,socklen_t option_len);
```

- getsocketopt 获取socket文件描述符属性
- setsocketopt 设置socket文件描述符属性



## 5.12 网络信息API

socket地址的两个要素，即IP地址和端口号，都是用数值表示的。这不便于记忆，也不便于扩展（比如从IPv4转移到IPv6）。因此在前面的章节中，我们用主机名来访问一台机器，而避免直接使用其IP地址。同样，我们用服务名称来代替端口号。比如，下面两条telnet命令具有完全相同的作用：
```c
telnet 127.0.0.1 80
telnet localhost www
```

- 上面的例子中，telnet客户端程序是通过调用某些网络信息API来实
  现主机名到IP地址的转换，以及服务名称到端口号的转换的。



# 6 高级I/O函数

## 6.1 pipe函数

创建一个管道，用于进程间通信

```c
#include＜unistd.h＞
int pipe(int fd[2]);
```

- 成功时返回0，并将一对打开的文件描述符值填入其参数指向的数组
- 失败，则返回-1并设置errno

fd[0] 是读端，fd[1] 是写端，两者不可调换，如果要实现双向传输，则需要建立两个管道

- 默认情况下，这一对文件描述符都是阻塞的
  - 此时如果我们用read系统调用来读取一个空的管道，则read将被阻塞，直到管道内有数据可读
  - 如果我们用write系统调用来往一个满的管道中写入数据，则write亦将被阻塞，直到管道有足够多的空闲空间可用
- 如果管道的写端文件描述符fd[1]的引用计数（见5.7节）减少至0，即没有任何进程需要往管道中写入数据，则针对该管道的读端文件描述符fd[0]的read操作将返回0，即读取到了文件结束标记（End Of File，EOF）
- 如果管道的读端文件描述符fd[0]的引用计数减少至0，即没有任何进程需要从管道读取数据，则针对该管道的写端文件描述符fd[1]的write操作将失败，并引发SIGPIPE信号

socket的基础API中有一个socketpair函数。它能够方便地**创建双向管道**。其定义如下：

```c
#include＜sys/types.h＞
#include＜sys/socket.h＞
int socketpair(int domain,int type,int protocol,int fd[2]);
```

- domain 只能使用UNIX本地协议族AF_UNIX，因为只能在本地使用这个双向管道
- 其创建的文件描述符既可读又可写
- 成功时返回0，失败时返回-1并设置errno



## 6.2 dup和dup2函数

希望把标准输入重定向到一个文件，或者把标准输出重定向到一个网络连接（比如CGI编程）。这可以通过下面的用于复制文件描述符的dup或dup2函数来实现：

```c
#include＜unistd.h＞
int dup(int file_descriptor);
int dup2(int file_descriptor_one,int file_descriptor_two);
```

- dup函数创建一个新的文件描述符，该新文件描述符和原有文件描述符file_descriptor指向相同的文件、管道或者网络连接
  - 且dup返回的文件描述符总是取**系统当前可用的最小整数值**
- dup2和dup类似，不过它将返回第一个不小于file_descriptor_two的整数值
- 失败时返回-1并设置errno

**使用dup和dup2创建的文件描述符不集成原文件描述符的属性**

- 比如close-on-exec和non-blocking等



## 6.3 readv函数和writev函数

readv函数将数据从文件描述符读到分散的内存块中，即分散读；
writev函数则将多块分散的内存数据一并写入文件描述符中，即集中
写

```c
#include＜sys/uio.h＞
ssize_t readv(int fd,const struct iovec*vector,int count)；
ssize_t writev(int fd,const struct iovec*vector,int count);
```

- fd参数是被操作的目标文件描述符。vector参数的类型是iovec结构数组。count参数是vector数组的长度
- 成功时返回读出/写入fd的字节数
- 失败则返回-1并设置errno



## 6.4 sendfile函数

**sendfile**函数在两个文件描述符之间直接传递数据（完全在内核中操作），从而避免了内核缓冲区和用户缓冲区之间的数据拷贝，效率很高，这被称为**零拷贝**

```c
#include＜sys/sendfile.h＞
ssize_t sendfile(int out_fd,int in_fd,off_t*offset,size_t count);
```

- out_fd参数是待写入内容的文件描述符，in_fd参数是待读出内容的文件描述符；offset参数指定从读入文件流的哪个位置开始读，如果为空，则使用读入文件流默认的起始位置；count参数指定在文件描述符in_fd和out_fd之间传输的字节数
- 成功时返回传输的字节数，失败时返回-1并设置errno
- in_fd 必须指向真实的文件，不能是socket和管道
- out_fd 必须是一个socket



## 6.5 mmap函数和munmap函数

mmap函数用于申请一段内存空间。我们可以将这段内存作为进程
间通信的共享内存，也可以将文件直接映射到其中。munmap函数则释放由mmap创建的这段内存空间。它们的定义如下：

```c
#include＜sys/mman.h＞
void*mmap(void*start,size_t length,int prot,int flags,int fd,off_t offset);
int munmap(void*start,size_t length);
```

- start参数允许用户使用某个特定的地址作为这段内存的起始地址。如果它被设置成NULL，则系统自动分配一个地址

- length参数指定内存段的长度

- prot参数用来设置内存段的访问权限。它可以取以下几个值的按位或：

  - ❑PROT_READ，内存段可读。
    ❑PROT_WRITE，内存段可写。
    ❑PROT_EXEC，内存段可执行。
    ❑PROT_NONE，内存段不能被访问。

- flags参数控制内存段内容被修改后程序的行为

  - | 常用值        | 含义                                                         |
    | ------------- | ------------------------------------------------------------ |
    | MAP_SHARED    | 在进程间共享这段内存。对该内存段的修改将反映到被映射的文件中。它提供了进程间共享内存的 POSIX 方法 |
    | MAP_PRIVATE   | 内存段为调用进程所私有。对该内存段的修改不会反映到被映射的文件中 |
    | MAP_ANONYMOUS | 这段内存不是从文件映射而来的。其内容被初始化为全 0。这种情况下，mmap 函数的最后两个参数将被忽略 |
    | MAP_FIXED     | 内存段必须位于 start 参数指定的地址处。start 必须是内存页大小（4096 字节）的整数倍 |
    | MAP_HUGETLB   | 按照“大内存页面”来分配内存空间。“大内存页面”的大小可通过 /proc/meminfo 文件来查看 |

- fd参数是被映射文件对应的文件描述符
  - 一般通过open系统调用获得
- offset参数设置从文件的何处开始映射（对于不需要读入整个文件的情况）
- mmap成功时返回指向目标内存区域的指针，失败则返回
  MAP_FAILED（(void*)-1）并设置errno
- munmap函数成功时返回0，失败则返回-1并设置errno



## 6.6 splice函数

splice函数用于在两个文件描述符之间移动数据，也是**零拷贝**操
作。splice函数的定义如下：

```c
#include＜fcntl.h＞
ssize_t splice(int fd_in,loff_t*off_in,int fd_out,loff_t*off_out,size_t len,unsigned int flags);
```

- fd_in 是待输入数据的文件描述符
  - 如果是一个管道，则 off_in 必须为 NULL
  - 否则 off_in 表示输入数据流从何处开始读取数据
- fd_out和off_out 的含义相同，但作用于输出数据流
- len 指定移动数据的长度
- flags 控制参数如何移动
- 调用成功时返回移动字节的数量
  - 可能返回0，表示没有数据需要移动，这发生在从管道中读取数据（fd_in是管道文件描述符）而该管道没有被写入任何数据时
- 失败时返回-1并设置errno

使用splice函数时，fd_in和fd_out必须至少有一个是管道文件描述符



## 6.7 tee函数

tee函数在两个管道文件描述符之间复制数据，也是零拷贝操作。它**不消耗数据，因此源文件描述符上的数据仍然可以用于后续的读操**
**作**

```c
#include＜fcntl.h＞
ssize_t tee(int fd_in,int fd_out,size_t len,unsigned int flags);
```

- fd_in 和 fd_out 必须都是管道
- 成功时返回在两个文件描述符之间复制的数据数量（字节数）
- 失败时返回-1并设置errno



## 6.8 fcntl函数

fcntl函数，正如其名字（file control）描述的那样，提供了对文件描述符的各种控制操作

```c
#include＜fcntl.h＞
int fcntl(int fd,int cmd,…);
```



# 7 Linux服务器程序规范



## 7.1 日志

### 7.1.1 Linux系统日志

Linux提供一个守护进程来处理系统日志——syslogd，不过现在的Linux系统上使用的都是它的升级版——rsyslogd

rsyslogd守护进程既能接收用户进程输出的日志，又能接收内核日
志

- 用户进程是通过调用syslog函数生成系统日志的；rsyslogd则监听该文件以获取用户进程的输出
- 内核日志由printk等函数打印至内核的环状缓存中，环状缓存的内容直接映射到/proc/kmsg文件中；rsyslogd则通过读取该文件获得内核日志

rsyslogd守护进程在接收到用户进程或内核输入的日志后，会把它们输出至某些特定的日志文件

![image-20240625155731333](./assets/image-20240625155731333.png)



### 7.1.2 syslog函数

```c
#include＜syslog.h＞
void syslog(int priority,const char*message,...);
```

该函数采用可变参数（第二个参数message和第三个参数…）来结
构化输出

`openlog`可以改变syslog的默认输出方式，进一步结构化日志内容

```c
#include＜syslog.h＞
void openlog(const char*ident,int logopt,int facility);
```

- ident参数指定的字符串将被添加到日志消息的日期和时间之后，它通常被设置为程序的名字
- logopt参数对后续syslog调用的行为进行配置
- facility参数可用来修改syslog函数中的默认设施值

**日志的过滤**

程序在开发阶段可能需要输出很多调试信息，而发布之后我们又需要将这些调试信息关闭：设置日志掩码，日志级别大于日志掩码的信息会被系统忽略

```c
#include＜syslog.h＞
int setlogmask(int maskpri);
```

- maskpri参数指定日志掩码值。该函数始终会成功，它返回调用进程先前的日志掩码值

**日志的关闭**

```c
#include＜syslog.h＞
void closelog();
```



## 7.2 用户信息

### 7.2.1 UID、EUID、GID和EGID

下面这一组函数可以获取和设置当前进程的真实用户ID（UID）、有效用户ID（EUID）、真实组ID（GID）和有效组ID（EGID）：

```c
#include＜sys/types.h＞
#include＜unistd.h＞
uid_t getuid();/*获取真实用户ID*/
uid_t geteuid();/*获取有效用户ID*/
gid_t getgid();/*获取真实组ID*/
gid_t getegid();/*获取有效组ID*/
int setuid(uid_t uid);/*设置真实用户ID*/
int seteuid(uid_t uid);/*设置有效用户ID*/
int setgid(gid_t gid);/*设置真实组ID*/
int setegid(gid_t gid);/*设置有效组ID*/
```

