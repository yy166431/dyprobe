//
// DYProbe.m
//
// 原生 ObjC 抓包探针，无 frida 依赖，TrollStore 兼容。
//
// 工作原理：
//   1. +load 时 method swizzle NSURLSession.dataTaskWithRequest:completionHandler:
//   2. 拦截命中 host = 106.53.173.140 的请求，记录 URL/headers/body
//   3. 包装 completionHandler，请求结束时把响应 body/statusCode 也存下来
//   4. dump 一次插件 BSS 64KB（libswiftMetal.dylib + 0x1734000）
//   5. 输出到 /var/mobile/Documents/dyprobe_dump.json
//
// 抓最多 8 个请求 + 8 个响应，每次 hex/ascii dump 前 8KB。
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <pthread.h>

#define DYP_TARGET_HOST   @"106.53.173.140"
#define DYP_MAX_REQ       8
#define DYP_MAX_CB        8
#define DYP_BSS_OFFSET    0x1734000
#define DYP_BSS_SIZE      0x10000
#define DYP_BODY_CAP      8192
#define DYP_PLUGIN_NAME_1 @"libswiftMetal.dylib"
#define DYP_PLUGIN_NAME_2 @"libswiftMetal_patched.dylib"

static NSMutableArray *gRequests   = nil;
static NSMutableArray *gCompletions= nil;
static NSDictionary  *gMeta        = nil;
static NSString      *gBssHex      = nil;
static NSString      *gBssBase     = nil;
static int            gReqCount    = 0;
static int            gCbCount     = 0;
static pthread_mutex_t gLock;
static NSString      *gOutputPath  = nil;

#pragma mark - Helpers

static NSString *DYPHexAsciiDump(NSData *data, NSUInteger cap) {
    if (!data || data.length == 0) return nil;
    NSUInteger n = MIN(data.length, cap);
    const unsigned char *bytes = data.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:n*2];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:n];
    for (NSUInteger i = 0; i < n; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
        unsigned char c = bytes[i];
        [ascii appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
    }
    return [NSString stringWithFormat:@"hex=%@\nascii=%@", hex, ascii];
}

static NSDictionary *DYPDataInfo(NSData *data) {
    if (!data) return nil;
    NSUInteger n = MIN(data.length, (NSUInteger)DYP_BODY_CAP);
    const unsigned char *bytes = data.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:n*2];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:n];
    for (NSUInteger i = 0; i < n; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
        unsigned char c = bytes[i];
        [ascii appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
    }
    return @{
        @"len": @(data.length),
        @"captured": @(n),
        @"hex": hex,
        @"ascii": ascii,
    };
}

static NSDictionary *DYPHeadersDict(NSURLRequest *req) {
    NSDictionary *h = req.allHTTPHeaderFields;
    if (!h) return @{};
    return [h copy];
}

static NSString *DYPDocPath(void) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *doc = paths.firstObject;
    if (!doc) doc = @"/var/mobile/Documents";
    return [doc stringByAppendingPathComponent:@"dyprobe_dump.json"];
}

static void DYPFlushDump(void) {
    pthread_mutex_lock(&gLock);
    NSDictionary *out = @{
        @"meta":         gMeta ?: @{},
        @"bss_snapshot": gBssHex ? @{@"base": gBssBase ?: @"", @"size": @(DYP_BSS_SIZE), @"hex": gBssHex} : [NSNull null],
        @"requests":     [gRequests copy] ?: @[],
        @"completions":  [gCompletions copy] ?: @[],
        @"finished":     @(gCbCount >= 1 || gReqCount >= DYP_MAX_REQ),
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

#pragma mark - Plugin module discovery

// 作者插件叫 libswiftMetal.dylib，但 Apple 系统也有同名的
// /usr/lib/swift/libswiftMetal.dylib (Metal Swift bindings)，所以必须用
// 完整路径过滤：只接受 *.app/Frameworks/* 下的命中。
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
        if (DYPIsPluginPath(full)) {
            NSString *base = full.lastPathComponent;
            const struct mach_header *mh = _dyld_get_image_header(i);
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            uintptr_t baseAddr = (uintptr_t)mh;
            uintptr_t bssAddr  = baseAddr + DYP_BSS_OFFSET;

            gMeta = @{
                @"plugin_name": base,
                @"plugin_path": full,
                @"plugin_base": [NSString stringWithFormat:@"0x%lx", baseAddr],
                @"plugin_slide":[NSString stringWithFormat:@"0x%lx", slide],
            };
            gBssBase = [NSString stringWithFormat:@"0x%lx", bssAddr];

            const unsigned char *p = (const unsigned char *)bssAddr;
            NSMutableString *hex = [NSMutableString stringWithCapacity:DYP_BSS_SIZE*2];
            for (int k = 0; k < DYP_BSS_SIZE; k++) {
                [hex appendFormat:@"%02x", p[k]];
            }
            gBssHex = hex;
            return;
        }
    }
    gMeta = @{@"plugin_name": @"NOT_LOADED"};
}

#pragma mark - Hook

typedef void (^DYPCompletionBlock)(NSData *, NSURLResponse *, NSError *);

static IMP gOrig_dataTaskWithRequest_completion = NULL;

@interface NSURLSession (DYProbe) @end
@implementation NSURLSession (DYProbe)

- (NSURLSessionDataTask *)dyp_dataTaskWithRequest:(NSURLRequest *)request
                                completionHandler:(DYPCompletionBlock)completionHandler {
    @try {
        NSString *host = request.URL.host;
        if (host && [host isEqualToString:DYP_TARGET_HOST]) {
            pthread_mutex_lock(&gLock);
            BOOL takeReq = (gReqCount < DYP_MAX_REQ);
            int reqIdx = ++gReqCount;
            pthread_mutex_unlock(&gLock);

            if (takeReq) {
                NSDictionary *info = @{
                    @"n":       @(reqIdx),
                    @"url":     request.URL.absoluteString ?: @"",
                    @"method":  request.HTTPMethod ?: @"",
                    @"headers": DYPHeadersDict(request) ?: @{},
                    @"body":    request.HTTPBody ? DYPDataInfo(request.HTTPBody) : [NSNull null],
                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                };
                pthread_mutex_lock(&gLock);
                [gRequests addObject:info];
                pthread_mutex_unlock(&gLock);

                DYPCompletionBlock orig = [completionHandler copy];
                DYPCompletionBlock wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
                    @try {
                        pthread_mutex_lock(&gLock);
                        BOOL takeCb = (gCbCount < DYP_MAX_CB);
                        int cbIdx = ++gCbCount;
                        pthread_mutex_unlock(&gLock);

                        if (takeCb) {
                            NSMutableDictionary *c = [NSMutableDictionary dictionary];
                            c[@"n"] = @(cbIdx);
                            c[@"req_n"] = @(reqIdx);
                            c[@"url"] = request.URL.absoluteString ?: @"";
                            c[@"data"] = data ? DYPDataInfo(data) : [NSNull null];
                            if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                                NSHTTPURLResponse *http = (NSHTTPURLResponse *)resp;
                                c[@"statusCode"] = @(http.statusCode);
                                c[@"resp_headers"] = http.allHeaderFields ?: @{};
                            }
                            if (err) {
                                c[@"err"] = @{@"code": @(err.code), @"domain": err.domain ?: @"", @"desc": err.localizedDescription ?: @""};
                            }
                            c[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
                            pthread_mutex_lock(&gLock);
                            [gCompletions addObject:c];
                            pthread_mutex_unlock(&gLock);
                            DYPFlushDump();
                        }
                    } @catch (NSException *e) {}
                    if (orig) orig(data, resp, err);
                };

                typedef NSURLSessionDataTask *(*Fn)(id, SEL, NSURLRequest *, DYPCompletionBlock);
                Fn fn = (Fn)gOrig_dataTaskWithRequest_completion;
                NSURLSessionDataTask *task = fn(self, @selector(dyp_dataTaskWithRequest:completionHandler:), request, wrapped);
                DYPFlushDump();
                return task;
            }
        }
    } @catch (NSException *e) {}

    typedef NSURLSessionDataTask *(*Fn)(id, SEL, NSURLRequest *, DYPCompletionBlock);
    Fn fn = (Fn)gOrig_dataTaskWithRequest_completion;
    return fn(self, @selector(dyp_dataTaskWithRequest:completionHandler:), request, completionHandler);
}

@end

#pragma mark - Install

static void DYPInstallSwizzle(void) {
    Class cls = NSClassFromString(@"NSURLSession");
    if (!cls) return;

    SEL origSel = @selector(dataTaskWithRequest:completionHandler:);
    SEL newSel  = @selector(dyp_dataTaskWithRequest:completionHandler:);

    Method origM = class_getInstanceMethod(cls, origSel);
    Method newM  = class_getInstanceMethod(cls, newSel);
    if (!origM || !newM) return;

    IMP origIMP = method_getImplementation(origM);
    IMP newIMP  = method_getImplementation(newM);

    BOOL added = class_addMethod(cls, origSel, newIMP, method_getTypeEncoding(newM));
    if (added) {
        gOrig_dataTaskWithRequest_completion = origIMP;
        class_replaceMethod(cls, newSel, origIMP, method_getTypeEncoding(origM));
    } else {
        gOrig_dataTaskWithRequest_completion = method_getImplementation(origM);
        method_exchangeImplementations(origM, newM);
    }
}

#pragma mark - Entry

__attribute__((constructor))
static void DYProbeInit(void) {
    pthread_mutex_init(&gLock, NULL);
    gRequests    = [[NSMutableArray alloc] init];
    gCompletions = [[NSMutableArray alloc] init];
    gOutputPath  = DYPDocPath();

    dispatch_async(dispatch_get_main_queue(), ^{
        DYPCapturePluginInfo();
        DYPInstallSwizzle();
        DYPFlushDump();
        NSLog(@"[DYProbe] installed, output=%@", gOutputPath);
    });
}
