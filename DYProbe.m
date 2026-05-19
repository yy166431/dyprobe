//
// DYProbe.m  — 极简版：只 hook connect，dump 所有 outbound TCP IP/port
//
// 之前 hook read/write/close 会跟 dyld 自己的 IO 撞死，导致抖音启动闪退。
// 这版只 hook connect 一个函数，最小侵入。
//
// 输出：
//   - connects[]：所有 TCP outbound 连接 (ip, port, ts)
//     用来确认作者后端 IP 是什么（106.53.173.140 / 还是换了？）
//   - bss_snapshot：libswiftMetal.dylib BSS 64KB 快照
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
#import <string.h>
#import <errno.h>

#define DYP_MAX_CONNECT_EVENTS  512
#define DYP_BSS_SIZE            0x10000
#define DYP_PLUGIN_NAME_1 @"libswiftMetal.dylib"
#define DYP_PLUGIN_NAME_2 @"libswiftMetal_patched.dylib"

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
static NSDictionary  *gMeta        = nil;
static NSString      *gBssHex      = nil;
static NSString      *gBssBase     = nil;
static int            gConnectCount= 0;
static pthread_mutex_t gLock;
static NSString      *gOutputPath  = nil;
static volatile int   gReady       = 0;

static int gDiagConnectCalls = 0;

#pragma mark - 原 connect 指针

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
static connect_fn g_orig_connect = NULL;

// iOS / macOS 直接发 BSD syscall connect (SYS_connect = 98)，
// 绕过 libsystem 完全避开 DYLD_INTERPOSE 拦截（dlopen + dlsym 也会被拦）。
// errno 由内核通过 carry flag + x0 返回值约定设置。
//
// ABI: x0=fd, x1=sockaddr*, x2=socklen, x16=syscall number, svc #0x80
// 返回：x0 = 0 成功 / -errno 失败（按 darwin 约定，carry set 表示出错）

static int dyp_raw_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)addr;
    register long x2 __asm__("x2") = (long)len;
    register long x16 __asm__("x16") = 98;  // SYS_connect
    __asm__ volatile (
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x16)
        : "memory", "cc"
    );
    // x0 < 0 表示 -errno，但 darwin 实际通过 carry flag 判断
    // 这里粗略处理：负值视为错误
    if (x0 < 0) {
        errno = (int)(-x0);
        return -1;
    }
    return (int)x0;
}

#pragma mark - Helpers

static BOOL DYPShouldIgnoreIP(uint32_t ipBE) {
    uint32_t ip = ntohl(ipBE);
    if ((ip & 0xFF000000) == 0x7F000000) return YES;  // 127/8
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return YES;  // 169.254/16
    if (ip == 0) return YES;
    return NO;
}

static NSString *DYPDocPath(void) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *doc = paths.firstObject;
    if (!doc) doc = @"/var/mobile/Documents";
    return [doc stringByAppendingPathComponent:@"dyprobe_dump.json"];
}

static void DYPAddConnectEvent(int fd, uint32_t ipBE, uint16_t portHE, int family) {
    pthread_mutex_lock(&gLock);
    if (gConnectCount >= DYP_MAX_CONNECT_EVENTS) {
        pthread_mutex_unlock(&gLock);
        return;
    }
    gConnectCount++;
    pthread_mutex_unlock(&gLock);

    char ipstr[INET_ADDRSTRLEN] = {0};
    if (family == AF_INET) {
        struct in_addr a; a.s_addr = ipBE;
        inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));
    }

    NSDictionary *e = @{
        @"fd": @(fd),
        @"ip": [NSString stringWithUTF8String:ipstr],
        @"port": @(portHE),
        @"family": @(family),
        @"ts": @([[NSDate date] timeIntervalSince1970]),
    };
    pthread_mutex_lock(&gLock);
    [gConnects addObject:e];
    pthread_mutex_unlock(&gLock);
}

static void DYPFlushDump(void) {
    pthread_mutex_lock(&gLock);
    NSDictionary *out = @{
        @"meta":         gMeta ?: @{},
        @"diag":         @{
            @"ready":          @(gReady),
            @"connect_calls":  @(gDiagConnectCalls),
            @"connect_events": @(gConnectCount),
        },
        @"bss_snapshot": gBssHex ? @{@"base": gBssBase ?: @"", @"size": @(DYP_BSS_SIZE), @"hex": gBssHex} : [NSNull null],
        @"connects":     [gConnects copy] ?: @[],
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

#pragma mark - INTERPOSE: connect only

int dyp_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    // 直接发 syscall，绕开 DYLD_INTERPOSE，避免无限递归
    int rv = dyp_raw_connect(fd, addr, len);

    // 只在 gReady 且 ObjC runtime 准备好后才记录
    if (!gReady || !gConnects) return rv;

    gDiagConnectCalls++;
    if (addr && len >= sizeof(struct sockaddr_in)) {
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
            if (!DYPShouldIgnoreIP(sin->sin_addr.s_addr)) {
                DYPAddConnectEvent(fd, sin->sin_addr.s_addr, ntohs(sin->sin_port), AF_INET);
            }
        } else if (addr->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
            DYPAddConnectEvent(fd, 0, ntohs(sin6->sin6_port), AF_INET6);
        }
    }
    return rv;
}
DYLD_INTERPOSE(dyp_connect, connect);

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

__attribute__((constructor(101)))
static void DYProbeResolveSymbols(void) {
    // 不需要解析符号了，dyp_connect 直接用 svc 发 syscall。
    // 这个 constructor 保留只是为了占位（早期 init），可能将来加诊断
}

__attribute__((constructor))
static void DYProbeInit(void) {
    pthread_mutex_init(&gLock, NULL);
    gConnects = [[NSMutableArray alloc] init];
    gOutputPath = DYPDocPath();

    // 1.5 秒后开 ready，给抖音启动期一点缓冲（实测 5s 太久）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        gReady = 1;
    });

    // 2 秒后抓 BSS
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        DYPCapturePluginInfo();
        DYPFlushDump();
    });

    // 周期 flush
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        while (1) {
            [NSThread sleepForTimeInterval:5.0];
            DYPFlushDump();
        }
    });
}
