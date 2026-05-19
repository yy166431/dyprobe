//
// DYProbe.m  — fishhook 版
//
// fishhook 替换 __la_symbol_ptr 段里的指针，data 段写入，绕开 PAC + interpose 递归坑。
//
// hook 目标：
//   - connect: 抓所有 outbound TCP IP/port
//   - SSL_write: 抓 boringssl 加密前的明文（HTTPS 请求 body）
//   - SSL_read: 抓 boringssl 解密后的明文（HTTPS 响应 body）
//
// 输出 /var/mobile/.../Documents/dyprobe_dump.json
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
#include "fishhook.h"

#define DYP_MAX_CONNECT_EVENTS  512
#define DYP_MAX_SSL_EVENTS      64
#define DYP_BSS_SIZE            0x10000
#define DYP_BUF_CAP             8192
#define DYP_PER_FD_MAX_BYTES    32768
#define DYP_PLUGIN_NAME_1 @"libswiftMetal.dylib"
#define DYP_PLUGIN_NAME_2 @"libswiftMetal_patched.dylib"

#pragma mark - 全局状态

static NSMutableArray *gConnects   = nil;
static NSMutableArray *gSslEvents  = nil;
static NSDictionary  *gMeta        = nil;
static NSString      *gBssHex      = nil;
static NSString      *gBssBase     = nil;
static int            gConnectCount= 0;
static int            gSslEventCount= 0;
static pthread_mutex_t gLock;
static NSString      *gOutputPath  = nil;
static volatile int   gReady       = 0;

// per-SSL-pointer 字节计数（防爆，每条 SSL* 最多抓 32KB）
#define DYP_MAX_SSL_TRACK 64
static struct {
    void *ssl;
    uint32_t bytes;
} gSslTrack[DYP_MAX_SSL_TRACK];

static int gDiagConnectCalls = 0;
static int gDiagSslWriteCalls = 0;
static int gDiagSslReadCalls  = 0;

#pragma mark - 原函数指针

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*SSL_write_fn)(void *ssl, const void *buf, int num);
typedef int (*SSL_read_fn)(void *ssl, void *buf, int num);

static connect_fn   g_orig_connect   = NULL;
static SSL_write_fn g_orig_SSL_write = NULL;
static SSL_read_fn  g_orig_SSL_read  = NULL;

#pragma mark - Helpers

static BOOL DYPShouldIgnoreIP(uint32_t ipBE) {
    uint32_t ip = ntohl(ipBE);
    if ((ip & 0xFF000000) == 0x7F000000) return YES;
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return YES;
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

static uint32_t DYPSslGetBytes(void *ssl) {
    for (int i = 0; i < DYP_MAX_SSL_TRACK; i++) {
        if (gSslTrack[i].ssl == ssl) return gSslTrack[i].bytes;
    }
    return 0;
}

static void DYPSslAddBytes(void *ssl, uint32_t add) {
    for (int i = 0; i < DYP_MAX_SSL_TRACK; i++) {
        if (gSslTrack[i].ssl == ssl) {
            gSslTrack[i].bytes += add;
            return;
        }
    }
    for (int i = 0; i < DYP_MAX_SSL_TRACK; i++) {
        if (gSslTrack[i].ssl == NULL) {
            gSslTrack[i].ssl = ssl;
            gSslTrack[i].bytes = add;
            return;
        }
    }
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

static void DYPAddSslEvent(NSString *op, void *ssl, const void *buf, int len) {
    if (len <= 0) return;
    if (DYPSslGetBytes(ssl) >= DYP_PER_FD_MAX_BYTES) return;
    pthread_mutex_lock(&gLock);
    if (gSslEventCount >= DYP_MAX_SSL_EVENTS) {
        pthread_mutex_unlock(&gLock);
        return;
    }
    gSslEventCount++;
    pthread_mutex_unlock(&gLock);

    DYPSslAddBytes(ssl, (uint32_t)len);
    NSDictionary *info = DYPDataInfo(buf, (size_t)len);
    NSDictionary *e = @{
        @"ssl": [NSString stringWithFormat:@"%p", ssl],
        @"op":  op,
        @"data": info,
        @"ts":  @([[NSDate date] timeIntervalSince1970]),
    };
    pthread_mutex_lock(&gLock);
    [gSslEvents addObject:e];
    pthread_mutex_unlock(&gLock);
}

static void DYPFlushDump(void) {
    pthread_mutex_lock(&gLock);
    NSDictionary *out = @{
        @"meta":         gMeta ?: @{},
        @"diag":         @{
            @"ready":           @(gReady),
            @"connect_calls":   @(gDiagConnectCalls),
            @"ssl_write_calls": @(gDiagSslWriteCalls),
            @"ssl_read_calls":  @(gDiagSslReadCalls),
            @"connect_events":  @(gConnectCount),
            @"ssl_events":      @(gSslEventCount),
        },
        @"bss_snapshot": gBssHex ? @{@"base": gBssBase ?: @"", @"size": @(DYP_BSS_SIZE), @"hex": gBssHex} : [NSNull null],
        @"connects":     [gConnects copy] ?: @[],
        @"ssl":          [gSslEvents copy] ?: @[],
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

#pragma mark - Hook 实现

// 注意：fishhook 是替换 __la_symbol_ptr，所以"原函数"被存到 g_orig_xxx，
// hook 调用 g_orig_xxx 不会递归（因为指向真实 libsystem/boringssl 实现）

static int dyp_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int rv = g_orig_connect ? g_orig_connect(fd, addr, len) : -1;
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

static int dyp_SSL_write(void *ssl, const void *buf, int num) {
    int rv = g_orig_SSL_write ? g_orig_SSL_write(ssl, buf, num) : 0;
    if (!gReady || !gSslEvents) return rv;
    gDiagSslWriteCalls++;
    // 只记成功的写入
    if (rv > 0) {
        DYPAddSslEvent(@"SSL_write", ssl, buf, num);
    }
    return rv;
}

static int dyp_SSL_read(void *ssl, void *buf, int num) {
    int rv = g_orig_SSL_read ? g_orig_SSL_read(ssl, buf, num) : 0;
    if (!gReady || !gSslEvents) return rv;
    gDiagSslReadCalls++;
    if (rv > 0) {
        DYPAddSslEvent(@"SSL_read", ssl, buf, rv);
    }
    return rv;
}

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

__attribute__((constructor))
static void DYProbeInit(void) {
    pthread_mutex_init(&gLock, NULL);
    gConnects = [[NSMutableArray alloc] init];
    gSslEvents = [[NSMutableArray alloc] init];
    gOutputPath = DYPDocPath();
    memset(gSslTrack, 0, sizeof(gSslTrack));

    // fishhook 重绑定：连同 boringssl 在内的所有 image 的 __la_symbol_ptr
    // 里凡是 connect/SSL_write/SSL_read 的引用，都改成我们的 dyp_xxx
    // g_orig_xxx 会被 fishhook 写入指向真实实现的指针
    struct rebinding rebs[3] = {
        {"connect",   (void *)dyp_connect,   (void **)&g_orig_connect},
        {"SSL_write", (void *)dyp_SSL_write, (void **)&g_orig_SSL_write},
        {"SSL_read",  (void *)dyp_SSL_read,  (void **)&g_orig_SSL_read},
    };
    rebind_symbols(rebs, 3);

    // 1.5 秒后 ready
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
