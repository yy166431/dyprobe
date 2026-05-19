//
// DYProbe.m  — 底层 socket 嗅探（智能过滤 + 启动期保护）
//
// 设计：
//   1. 抖音启动期 hook 只透传不记录（gReady=0），避免死锁/卡启动
//   2. 5 秒后开 gReady=1，开始抓包
//   3. 抓所有 outbound TCP connect（看作者新 IP）
//   4. fd 第一次 send 时检测 HTTP 明文 → 是就抓 IO，不是（TLS / 二进制）就忽略
//   5. per-fd 16KB 上限 + 全局 64 IO + 256 connect
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <pthread.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <sys/uio.h>
#import <string.h>

#define DYP_MAX_CONNECT_EVENTS  256
#define DYP_MAX_IO_EVENTS       64
#define DYP_BSS_SIZE            0x10000
#define DYP_BUF_CAP             8192
#define DYP_PER_FD_MAX_BYTES    16384
#define DYP_PLUGIN_NAME_1 @"libswiftMetal.dylib"
#define DYP_PLUGIN_NAME_2 @"libswiftMetal_patched.dylib"
#define DYP_READY_DELAY_SEC     5.0

#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacement, \
        (const void *)(unsigned long)&_replacee \
    };

#pragma mark - 全局状态

static NSMutableArray *gConnects   = nil;
static NSMutableArray *gIoEvents   = nil;
static NSDictionary  *gMeta        = nil;
static NSString      *gBssHex      = nil;
static NSString      *gBssBase     = nil;
static int            gConnectCount= 0;
static int            gIoEventCount= 0;
static pthread_mutex_t gLock;
static NSString      *gOutputPath  = nil;

#define DYP_FD_UNKNOWN  0
#define DYP_FD_CAPTURE  1
#define DYP_FD_IGNORE   2
#define DYP_MAX_FD      16384
static uint8_t  gFdState[DYP_MAX_FD];
static uint32_t gFdBytesSeen[DYP_MAX_FD];
static uint32_t gFdDstIp[DYP_MAX_FD];
static uint16_t gFdDstPort[DYP_MAX_FD];

static volatile int gReady = 0;  // hook 只在 gReady=1 时记录

static int gDiagConnectCalls    = 0;
static int gDiagSendCalls       = 0;
static int gDiagWriteCalls      = 0;
static int gDiagWritevCalls     = 0;
static int gDiagRecvCalls       = 0;
static int gDiagReadCalls       = 0;
static int gDiagFdHttpMarked    = 0;
static int gDiagFdIgnoreMarked  = 0;

#pragma mark - 原函数指针（dlsym 一次性解析）

typedef int      (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef ssize_t  (*send_fn)(int, const void *, size_t, int);
typedef ssize_t  (*sendto_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t  (*write_fn)(int, const void *, size_t);
typedef ssize_t  (*writev_fn)(int, const struct iovec *, int);
typedef ssize_t  (*recv_fn)(int, void *, size_t, int);
typedef ssize_t  (*recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t  (*read_fn)(int, void *, size_t);
typedef ssize_t  (*readv_fn)(int, const struct iovec *, int);
typedef int      (*close_fn)(int);

static connect_fn   g_orig_connect  = NULL;
static send_fn      g_orig_send     = NULL;
static sendto_fn    g_orig_sendto   = NULL;
static write_fn     g_orig_write    = NULL;
static writev_fn    g_orig_writev   = NULL;
static recv_fn      g_orig_recv     = NULL;
static recvfrom_fn  g_orig_recvfrom = NULL;
static read_fn      g_orig_read     = NULL;
static readv_fn     g_orig_readv    = NULL;
static close_fn     g_orig_close    = NULL;

#pragma mark - Helpers

static BOOL DYPLooksLikeHTTP(const void *buf, size_t len) {
    if (!buf || len < 4) return NO;
    const char *p = (const char *)buf;
    static const char *methods[] = {
        "GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC", "TRAC", "CONN"
    };
    for (size_t i = 0; i < sizeof(methods)/sizeof(methods[0]); i++) {
        if (memcmp(p, methods[i], 4) == 0) return YES;
    }
    return NO;
}

static BOOL DYPShouldIgnoreIP(uint32_t ipBE) {
    uint32_t ip = ntohl(ipBE);
    if ((ip & 0xFF000000) == 0x7F000000) return YES;  // 127/8
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return YES;  // 169.254/16
    if (ip == 0) return YES;
    return NO;
}

static NSDictionary *DYPDataInfo(const void *buf, size_t len) {
    if (!buf || len == 0) return @{@"len": @(len)};
    size_t n = MIN(len, (size_t)DYP_BUF_CAP);
    const unsigned char *bytes = (const unsigned char *)buf;
    NSMutableString *hex = [NSMutableString stringWithCapacity:n*2];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:n];
    for (size_t i = 0; i < n; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
        unsigned char c = bytes[i];
        [ascii appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
    }
    return @{@"len": @(len), @"captured": @(n), @"hex": hex, @"ascii": ascii};
}

static NSString *DYPDocPath(void) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *doc = paths.firstObject;
    if (!doc) doc = @"/var/mobile/Documents";
    return [doc stringByAppendingPathComponent:@"dyprobe_dump.json"];
}

static void DYPAddConnectEvent(int fd, uint32_t ipBE, uint16_t portHE) {
    pthread_mutex_lock(&gLock);
    if (gConnectCount >= DYP_MAX_CONNECT_EVENTS) {
        pthread_mutex_unlock(&gLock);
        return;
    }
    gConnectCount++;
    pthread_mutex_unlock(&gLock);

    char ipstr[INET_ADDRSTRLEN] = {0};
    struct in_addr a; a.s_addr = ipBE;
    inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));

    NSDictionary *e = @{
        @"fd": @(fd),
        @"ip": [NSString stringWithUTF8String:ipstr],
        @"port": @(portHE),
        @"ts": @([[NSDate date] timeIntervalSince1970]),
    };
    pthread_mutex_lock(&gLock);
    [gConnects addObject:e];
    pthread_mutex_unlock(&gLock);
}

static void DYPAddIoEvent(int fd, NSString *op, const void *buf, ssize_t len) {
    if (len <= 0 || fd < 0 || fd >= DYP_MAX_FD) return;
    if (gFdBytesSeen[fd] >= DYP_PER_FD_MAX_BYTES) return;
    pthread_mutex_lock(&gLock);
    if (gIoEventCount >= DYP_MAX_IO_EVENTS) {
        pthread_mutex_unlock(&gLock);
        return;
    }
    gIoEventCount++;
    pthread_mutex_unlock(&gLock);

    uint32_t allowed = DYP_PER_FD_MAX_BYTES - gFdBytesSeen[fd];
    size_t take = MIN((size_t)len, (size_t)allowed);
    gFdBytesSeen[fd] += take;

    char ipstr[INET_ADDRSTRLEN] = {0};
    struct in_addr a; a.s_addr = gFdDstIp[fd];
    inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));

    NSDictionary *info = DYPDataInfo(buf, take);
    NSDictionary *e = @{
        @"fd": @(fd),
        @"op": op,
        @"ip": [NSString stringWithUTF8String:ipstr],
        @"port": @(gFdDstPort[fd]),
        @"data": info,
        @"ts": @([[NSDate date] timeIntervalSince1970]),
    };
    pthread_mutex_lock(&gLock);
    [gIoEvents addObject:e];
    pthread_mutex_unlock(&gLock);
}

static void DYPMaybeMarkFdHttp(int fd, const void *buf, size_t len) {
    if (fd < 0 || fd >= DYP_MAX_FD) return;
    if (gFdState[fd] != DYP_FD_UNKNOWN) return;
    if (gFdDstIp[fd] == 0) return;
    if (DYPLooksLikeHTTP(buf, len)) {
        gFdState[fd] = DYP_FD_CAPTURE;
        gDiagFdHttpMarked++;
    } else {
        gFdState[fd] = DYP_FD_IGNORE;
        gDiagFdIgnoreMarked++;
    }
}

static void DYPFlushDump(void) {
    pthread_mutex_lock(&gLock);
    NSDictionary *out = @{
        @"meta":         gMeta ?: @{},
        @"diag":         @{
            @"ready":             @(gReady),
            @"connect_calls":     @(gDiagConnectCalls),
            @"send_calls":        @(gDiagSendCalls),
            @"write_calls":       @(gDiagWriteCalls),
            @"writev_calls":      @(gDiagWritevCalls),
            @"recv_calls":        @(gDiagRecvCalls),
            @"read_calls":        @(gDiagReadCalls),
            @"fd_http_marked":    @(gDiagFdHttpMarked),
            @"fd_ignore_marked":  @(gDiagFdIgnoreMarked),
            @"connect_events":    @(gConnectCount),
            @"io_events":         @(gIoEventCount),
        },
        @"bss_snapshot": gBssHex ? @{@"base": gBssBase ?: @"", @"size": @(DYP_BSS_SIZE), @"hex": gBssHex} : [NSNull null],
        @"connects":     [gConnects copy] ?: @[],
        @"io":           [gIoEvents copy] ?: @[],
    };
    NSError *err = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:out
                                                   options:NSJSONWritingPrettyPrinted
                                                     error:&err];
    if (json && gOutputPath) {
        [json writeToFile:gOutputPath atomically:YES];
    }
    pthread_mutex_unlock(&gLock);
}

#pragma mark - INTERPOSE hooks
//
// 模式：先调原函数（拿到结果），然后才决定是否记录。
// gReady=0 时直接透传，避免抖音启动期 IO 风暴 + Foundation/ObjC 初始化死锁。
// 所有 ObjC 操作（NSMutableArray addObject 等）只在 gReady=1 后才走。
//

int dyp_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int rv = g_orig_connect(fd, addr, len);
    if (!gReady) return rv;
    gDiagConnectCalls++;
    if (addr && addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        if (!DYPShouldIgnoreIP(sin->sin_addr.s_addr)) {
            if (fd >= 0 && fd < DYP_MAX_FD) {
                gFdDstIp[fd]   = sin->sin_addr.s_addr;
                gFdDstPort[fd] = ntohs(sin->sin_port);
                gFdState[fd]   = DYP_FD_UNKNOWN;
                gFdBytesSeen[fd] = 0;
            }
            DYPAddConnectEvent(fd, sin->sin_addr.s_addr, ntohs(sin->sin_port));
        }
    }
    return rv;
}
DYLD_INTERPOSE(dyp_connect, connect);

ssize_t dyp_send(int fd, const void *buf, size_t len, int flags) {
    ssize_t rv = g_orig_send(fd, buf, len, flags);
    if (!gReady) return rv;
    gDiagSendCalls++;
    if (fd >= 0 && fd < DYP_MAX_FD && gFdDstIp[fd] != 0) {
        if (gFdState[fd] == DYP_FD_UNKNOWN) DYPMaybeMarkFdHttp(fd, buf, len);
        if (gFdState[fd] == DYP_FD_CAPTURE) DYPAddIoEvent(fd, @"send", buf, (ssize_t)len);
    }
    return rv;
}
DYLD_INTERPOSE(dyp_send, send);

ssize_t dyp_sendto(int fd, const void *buf, size_t len, int flags,
                   const struct sockaddr *to, socklen_t tolen) {
    ssize_t rv = g_orig_sendto(fd, buf, len, flags, to, tolen);
    if (!gReady) return rv;
    if (fd >= 0 && fd < DYP_MAX_FD && gFdDstIp[fd] != 0) {
        if (gFdState[fd] == DYP_FD_UNKNOWN) DYPMaybeMarkFdHttp(fd, buf, len);
        if (gFdState[fd] == DYP_FD_CAPTURE) DYPAddIoEvent(fd, @"sendto", buf, (ssize_t)len);
    }
    return rv;
}
DYLD_INTERPOSE(dyp_sendto, sendto);

ssize_t dyp_write(int fd, const void *buf, size_t count) {
    ssize_t rv = g_orig_write(fd, buf, count);
    if (!gReady) return rv;
    gDiagWriteCalls++;
    if (fd >= 0 && fd < DYP_MAX_FD && gFdDstIp[fd] != 0) {
        if (gFdState[fd] == DYP_FD_UNKNOWN) DYPMaybeMarkFdHttp(fd, buf, count);
        if (gFdState[fd] == DYP_FD_CAPTURE) DYPAddIoEvent(fd, @"write", buf, (ssize_t)count);
    }
    return rv;
}
DYLD_INTERPOSE(dyp_write, write);

ssize_t dyp_writev(int fd, const struct iovec *iov, int iovcnt) {
    ssize_t rv = g_orig_writev(fd, iov, iovcnt);
    if (!gReady) return rv;
    gDiagWritevCalls++;
    if (fd >= 0 && fd < DYP_MAX_FD && gFdDstIp[fd] != 0 && iov && iovcnt > 0) {
        if (gFdState[fd] == DYP_FD_UNKNOWN && iov[0].iov_base) {
            DYPMaybeMarkFdHttp(fd, iov[0].iov_base, MIN(iov[0].iov_len, (size_t)256));
        }
        if (gFdState[fd] == DYP_FD_CAPTURE) {
            size_t total = 0;
            for (int i = 0; i < iovcnt; i++) total += iov[i].iov_len;
            size_t cap = MIN(total, (size_t)DYP_BUF_CAP);
            void *buf = malloc(cap);
            if (buf) {
                size_t off = 0;
                for (int i = 0; i < iovcnt && off < cap; i++) {
                    size_t take = MIN(iov[i].iov_len, cap - off);
                    memcpy((char *)buf + off, iov[i].iov_base, take);
                    off += take;
                }
                DYPAddIoEvent(fd, @"writev", buf, (ssize_t)off);
                free(buf);
            }
        }
    }
    return rv;
}
DYLD_INTERPOSE(dyp_writev, writev);

ssize_t dyp_recv(int fd, void *buf, size_t len, int flags) {
    ssize_t r = g_orig_recv(fd, buf, len, flags);
    if (!gReady) return r;
    gDiagRecvCalls++;
    if (r > 0 && fd >= 0 && fd < DYP_MAX_FD && gFdState[fd] == DYP_FD_CAPTURE) {
        DYPAddIoEvent(fd, @"recv", buf, r);
    }
    return r;
}
DYLD_INTERPOSE(dyp_recv, recv);

ssize_t dyp_recvfrom(int fd, void *buf, size_t len, int flags,
                     struct sockaddr *from, socklen_t *fromlen) {
    ssize_t r = g_orig_recvfrom(fd, buf, len, flags, from, fromlen);
    if (!gReady) return r;
    if (r > 0 && fd >= 0 && fd < DYP_MAX_FD && gFdState[fd] == DYP_FD_CAPTURE) {
        DYPAddIoEvent(fd, @"recvfrom", buf, r);
    }
    return r;
}
DYLD_INTERPOSE(dyp_recvfrom, recvfrom);

ssize_t dyp_read(int fd, void *buf, size_t count) {
    ssize_t r = g_orig_read(fd, buf, count);
    if (!gReady) return r;
    gDiagReadCalls++;
    if (r > 0 && fd >= 0 && fd < DYP_MAX_FD && gFdState[fd] == DYP_FD_CAPTURE) {
        DYPAddIoEvent(fd, @"read", buf, r);
    }
    return r;
}
DYLD_INTERPOSE(dyp_read, read);

ssize_t dyp_readv(int fd, const struct iovec *iov, int iovcnt) {
    ssize_t r = g_orig_readv(fd, iov, iovcnt);
    if (!gReady) return r;
    if (r > 0 && fd >= 0 && fd < DYP_MAX_FD && gFdState[fd] == DYP_FD_CAPTURE && iov && iovcnt > 0) {
        size_t cap = MIN((size_t)r, (size_t)DYP_BUF_CAP);
        void *buf = malloc(cap);
        if (buf) {
            size_t off = 0;
            for (int i = 0; i < iovcnt && off < cap; i++) {
                size_t take = MIN(iov[i].iov_len, cap - off);
                memcpy((char *)buf + off, iov[i].iov_base, take);
                off += take;
            }
            DYPAddIoEvent(fd, @"readv", buf, (ssize_t)off);
            free(buf);
        }
    }
    return r;
}
DYLD_INTERPOSE(dyp_readv, readv);

int dyp_close(int fd) {
    if (gReady && fd >= 0 && fd < DYP_MAX_FD) {
        gFdState[fd] = 0;
        gFdDstIp[fd] = 0;
        gFdDstPort[fd] = 0;
        gFdBytesSeen[fd] = 0;
    }
    return g_orig_close(fd);
}
DYLD_INTERPOSE(dyp_close, close);

#pragma mark - Plugin BSS dump

static BOOL DYPIsPluginPath(NSString *full) {
    if (!full) return NO;
    if ([full hasPrefix:@"/usr/lib/"]) return NO;
    if ([full hasPrefix:@"/System/"])  return NO;
    if ([full rangeOfString:@".app/Frameworks/"].location == NSNotFound) return NO;
    NSString *base = full.lastPathComponent;
    return [base isEqualToString:DYP_PLUGIN_NAME_1] || [base isEqualToString:DYP_PLUGIN_NAME_2];
}

static void DYPCapturePluginInfo(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        NSString *full = [NSString stringWithUTF8String:name];
        if (!DYPIsPluginPath(full)) continue;

        NSString *base = full.lastPathComponent;
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        uintptr_t baseAddr = (uintptr_t)mh;

        uintptr_t bssRuntimeAddr = 0;
        uint64_t  bssVmAddr = 0;
        uint64_t  bssVmSize = 0;
        const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                if (strncmp(seg->segname, "__DATA", 16) == 0) {
                    const struct section_64 *sect = (const struct section_64 *)(p + sizeof(struct segment_command_64));
                    for (uint32_t s = 0; s < seg->nsects; s++) {
                        if (strncmp(sect[s].sectname, "__bss", 16) == 0) {
                            bssVmAddr = sect[s].addr;
                            bssVmSize = sect[s].size;
                            bssRuntimeAddr = (uintptr_t)(sect[s].addr + slide);
                            break;
                        }
                    }
                }
            }
            if (bssRuntimeAddr) break;
            p += lc->cmdsize;
        }

        uintptr_t dumpStart = bssRuntimeAddr ?: (baseAddr + 0x1734000);
        size_t dumpSize = DYP_BSS_SIZE;

        gMeta = @{
            @"plugin_name": base,
            @"plugin_path": full,
            @"plugin_base": [NSString stringWithFormat:@"0x%lx", baseAddr],
            @"plugin_slide":[NSString stringWithFormat:@"0x%lx", slide],
            @"bss_vmaddr":  [NSString stringWithFormat:@"0x%llx", bssVmAddr],
            @"bss_vmsize":  [NSString stringWithFormat:@"0x%llx", bssVmSize],
        };
        gBssBase = [NSString stringWithFormat:@"0x%lx", dumpStart];

        const unsigned char *bp = (const unsigned char *)dumpStart;
        NSMutableString *hex = [NSMutableString stringWithCapacity:dumpSize*2];
        for (size_t k = 0; k < dumpSize; k++) {
            [hex appendFormat:@"%02x", bp[k]];
        }
        gBssHex = hex;
        return;
    }
    gMeta = @{@"plugin_name": @"NOT_LOADED"};
}

#pragma mark - Entry

// 优先级 101，确保比默认 constructor 早，能在第一次 socket 调用前解析符号
__attribute__((constructor(101)))
static void DYProbeResolveSymbols(void) {
    g_orig_connect  = (connect_fn) dlsym(RTLD_NEXT, "connect");
    g_orig_send     = (send_fn)    dlsym(RTLD_NEXT, "send");
    g_orig_sendto   = (sendto_fn)  dlsym(RTLD_NEXT, "sendto");
    g_orig_write    = (write_fn)   dlsym(RTLD_NEXT, "write");
    g_orig_writev   = (writev_fn)  dlsym(RTLD_NEXT, "writev");
    g_orig_recv     = (recv_fn)    dlsym(RTLD_NEXT, "recv");
    g_orig_recvfrom = (recvfrom_fn)dlsym(RTLD_NEXT, "recvfrom");
    g_orig_read     = (read_fn)    dlsym(RTLD_NEXT, "read");
    g_orig_readv    = (readv_fn)   dlsym(RTLD_NEXT, "readv");
    g_orig_close    = (close_fn)   dlsym(RTLD_NEXT, "close");
}

__attribute__((constructor))
static void DYProbeInit(void) {
    pthread_mutex_init(&gLock, NULL);
    gConnects = [[NSMutableArray alloc] init];
    gIoEvents = [[NSMutableArray alloc] init];
    gOutputPath = DYPDocPath();
    memset(gFdState, 0, sizeof(gFdState));
    memset(gFdBytesSeen, 0, sizeof(gFdBytesSeen));
    memset(gFdDstIp, 0, sizeof(gFdDstIp));
    memset(gFdDstPort, 0, sizeof(gFdDstPort));

    // 抓 BSS（也是延迟到主队列，避免阻塞 dyld init）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        DYPCapturePluginInfo();
        DYPFlushDump();
    });

    // gReady 延迟开启：抖音启动完成后才开始记录事件
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(DYP_READY_DELAY_SEC * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        gReady = 1;
    });

    // 周期性 flush
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        while (1) {
            [NSThread sleepForTimeInterval:5.0];
            DYPFlushDump();
        }
    });
}
