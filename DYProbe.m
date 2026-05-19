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
#import <mach-o/loader.h>
#import <pthread.h>

#define DYP_TARGET_HOST   @"106.53.173.140"
#define DYP_MAX_REQ       8
#define DYP_MAX_CB        8

// BSS section 起始偏移因 dylib 版本而异。我们通过解析 Mach-O 自己定位
// __DATA segment 的 vmaddr，再加上每版 BSS 在 __DATA 内的相对位置。
// 实测：
//   v260512-21: __DATA.vmaddr=0x12f4000  __bss=0x17330e0  rel=0x43F0E0
//   v260513-22: __DATA.vmaddr=0x1354000  __bss=0x1792368  rel=0x43E368
// 差距很小 (~3KB)，统一用动态解析。
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
        @"diag":         @{
            @"subclass_count":     @(gDiagSubclassCount),
            @"data_hook_calls":    @(gDiagDataHookCount),
            @"upload_hook_calls":  @(gDiagUploadHookCount),
            @"resume_hook_calls":  @(gDiagResumeHookCount),
            @"resume_hit_target":  @(gDiagResumeHitTarget),
        },
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
            const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            uintptr_t baseAddr = (uintptr_t)mh;

            // 解析 LC_SEGMENT_64 找 __DATA.__bss section（带 __common 一起夹）
            // 找到的 addr 是 vmaddr，加 slide 得到运行时地址
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

            // BSS section 通常 ~0x1cd8 字节，太小，扩展到 0x10000 把 __common
            // 和邻接的 __data 尾部一起抓，方便 diff
            uintptr_t dumpStart = bssRuntimeAddr;
            size_t dumpSize = DYP_BSS_SIZE;
            if (!dumpStart) {
                // fallback: 旧版固定偏移
                dumpStart = baseAddr + 0x1734000;
            }

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
    }
    gMeta = @{@"plugin_name": @"NOT_LOADED"};
}

#pragma mark - Hook

typedef void (^DYPCompletionBlock)(NSData *, NSURLResponse *, NSError *);

// Hook 设计说明：
// NSURLSession 是 class cluster，调用方用 NSURLSession 父类指针拿到的实际是
// __NSURLSessionLocal / __NSCFURLLocalSession 等私有子类。class_getInstanceMethod
// 在父类上拿不到子类的 IMP 重写 → swizzle 父类对子类调用无效。
//
// 解决方案：
//   1) 遍历 objc 类列表，把 NSURLSession 所有子类都 swizzle 一遍
//   2) Hook NSURLSessionTask -resume：所有 task 类型最终都调它，覆盖率 100%
//   3) 通过 task 的 currentRequest / originalRequest 拿 URL，KVO 监听 state 拿响应

static IMP gOrig_dataTask_completion = NULL;
static IMP gOrig_uploadTask_completion = NULL;
static IMP gOrig_taskResume = NULL;

// 已 swizzle 过的 class 集合（避免重复）
static NSMutableSet *gSwizzledClasses = nil;

static int  gDiagSubclassCount = 0;
static int  gDiagDataHookCount = 0;
static int  gDiagUploadHookCount = 0;
static int  gDiagResumeHookCount = 0;
static int  gDiagResumeHitTarget = 0;

static NSMutableDictionary *gTaskMap = nil;  // task pointer -> reqIdx (NSNumber)

// 通用：包装 completionHandler 用，captures reqIdx + url
static DYPCompletionBlock DYPWrapCompletion(int reqIdx, NSString *url, DYPCompletionBlock orig) {
    DYPCompletionBlock origCopy = [orig copy];
    return ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try {
            pthread_mutex_lock(&gLock);
            BOOL takeCb = (gCbCount < DYP_MAX_CB);
            int cbIdx = ++gCbCount;
            pthread_mutex_unlock(&gLock);

            if (takeCb) {
                NSMutableDictionary *c = [NSMutableDictionary dictionary];
                c[@"n"] = @(cbIdx);
                c[@"req_n"] = @(reqIdx);
                c[@"url"] = url ?: @"";
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
        if (origCopy) origCopy(data, resp, err);
    };
}

// 通用：记录 request
static int DYPRecordRequest(NSURLRequest *request, NSString *kind, NSData *uploadData) {
    pthread_mutex_lock(&gLock);
    BOOL takeReq = (gReqCount < DYP_MAX_REQ);
    int reqIdx = ++gReqCount;
    pthread_mutex_unlock(&gLock);
    if (!takeReq) return reqIdx;

    NSData *body = uploadData ?: request.HTTPBody;
    NSDictionary *info = @{
        @"n":       @(reqIdx),
        @"kind":    kind ?: @"data",
        @"url":     request.URL.absoluteString ?: @"",
        @"method":  request.HTTPMethod ?: @"",
        @"headers": DYPHeadersDict(request) ?: @{},
        @"body":    body ? DYPDataInfo(body) : [NSNull null],
        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
    };
    pthread_mutex_lock(&gLock);
    [gRequests addObject:info];
    pthread_mutex_unlock(&gLock);
    DYPFlushDump();
    return reqIdx;
}

@interface NSURLSession (DYProbe) @end
@implementation NSURLSession (DYProbe)

- (NSURLSessionDataTask *)dyp_dataTaskWithRequest:(NSURLRequest *)request
                                completionHandler:(DYPCompletionBlock)completionHandler {
    gDiagDataHookCount++;
    @try {
        NSString *host = request.URL.host;
        if (host && [host isEqualToString:DYP_TARGET_HOST]) {
            int reqIdx = DYPRecordRequest(request, @"data", nil);
            NSString *url = request.URL.absoluteString;
            DYPCompletionBlock wrapped = completionHandler ? DYPWrapCompletion(reqIdx, url, completionHandler) : nil;

            typedef NSURLSessionDataTask *(*Fn)(id, SEL, NSURLRequest *, DYPCompletionBlock);
            Fn fn = (Fn)gOrig_dataTask_completion;
            return fn(self, @selector(dyp_dataTaskWithRequest:completionHandler:), request, wrapped);
        }
    } @catch (NSException *e) {}

    typedef NSURLSessionDataTask *(*Fn)(id, SEL, NSURLRequest *, DYPCompletionBlock);
    Fn fn = (Fn)gOrig_dataTask_completion;
    return fn(self, @selector(dyp_dataTaskWithRequest:completionHandler:), request, completionHandler);
}

- (NSURLSessionUploadTask *)dyp_uploadTaskWithRequest:(NSURLRequest *)request
                                             fromData:(NSData *)bodyData
                                    completionHandler:(DYPCompletionBlock)completionHandler {
    gDiagUploadHookCount++;
    @try {
        NSString *host = request.URL.host;
        if (host && [host isEqualToString:DYP_TARGET_HOST]) {
            int reqIdx = DYPRecordRequest(request, @"upload", bodyData);
            NSString *url = request.URL.absoluteString;
            DYPCompletionBlock wrapped = completionHandler ? DYPWrapCompletion(reqIdx, url, completionHandler) : nil;

            typedef NSURLSessionUploadTask *(*Fn)(id, SEL, NSURLRequest *, NSData *, DYPCompletionBlock);
            Fn fn = (Fn)gOrig_uploadTask_completion;
            return fn(self, @selector(dyp_uploadTaskWithRequest:fromData:completionHandler:), request, bodyData, wrapped);
        }
    } @catch (NSException *e) {}

    typedef NSURLSessionUploadTask *(*Fn)(id, SEL, NSURLRequest *, NSData *, DYPCompletionBlock);
    Fn fn = (Fn)gOrig_uploadTask_completion;
    return fn(self, @selector(dyp_uploadTaskWithRequest:fromData:completionHandler:), request, bodyData, completionHandler);
}

@end

#pragma mark - NSURLSessionTask -resume hook

@interface NSURLSessionTask (DYProbe) @end
@implementation NSURLSessionTask (DYProbe)

- (void)dyp_resume {
    gDiagResumeHookCount++;
    @try {
        // task 自己有 currentRequest / originalRequest
        NSURLRequest *req = nil;
        if ([self respondsToSelector:@selector(originalRequest)]) {
            req = [(id)self performSelector:@selector(originalRequest)];
        }
        if (!req && [self respondsToSelector:@selector(currentRequest)]) {
            req = [(id)self performSelector:@selector(currentRequest)];
        }
        if (req) {
            NSString *host = req.URL.host;
            if (host && [host isEqualToString:DYP_TARGET_HOST]) {
                gDiagResumeHitTarget++;
                // 只记录一次（基于 task 指针 dedup）
                NSValue *key = [NSValue valueWithPointer:(__bridge void *)self];
                pthread_mutex_lock(&gLock);
                BOOL alreadySeen = (gTaskMap[key] != nil);
                pthread_mutex_unlock(&gLock);

                if (!alreadySeen) {
                    NSString *kind = NSStringFromClass([self class]);
                    int reqIdx = DYPRecordRequest(req, kind, nil);
                    pthread_mutex_lock(&gLock);
                    gTaskMap[key] = @(reqIdx);
                    pthread_mutex_unlock(&gLock);
                }
            }
        }
    } @catch (NSException *e) {}

    typedef void (*Fn)(id, SEL);
    Fn fn = (Fn)gOrig_taskResume;
    fn(self, @selector(dyp_resume));
}

@end

#pragma mark - Install

static void DYPSwizzleOne(Class cls, SEL origSel, SEL newSel, IMP *outOrigIMP) {
    Method origM = class_getInstanceMethod(cls, origSel);
    Method newM  = class_getInstanceMethod(cls, newSel);
    if (!origM || !newM) return;
    IMP origIMP = method_getImplementation(origM);
    IMP newIMP  = method_getImplementation(newM);
    BOOL added = class_addMethod(cls, origSel, newIMP, method_getTypeEncoding(newM));
    if (added) {
        *outOrigIMP = origIMP;
        class_replaceMethod(cls, newSel, origIMP, method_getTypeEncoding(origM));
    } else {
        *outOrigIMP = method_getImplementation(origM);
        method_exchangeImplementations(origM, newM);
    }
}

// 遍历所有 NSURLSession 子类，逐个 swizzle
static void DYPSwizzleSessionSubclass(Class cls) {
    NSString *name = NSStringFromClass(cls);
    NSValue *key = [NSValue valueWithPointer:(__bridge void *)cls];
    if ([gSwizzledClasses containsObject:key]) return;
    [gSwizzledClasses addObject:key];
    gDiagSubclassCount++;

    // dataTask
    Method dataM = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
    if (dataM) {
        IMP origIMP = NULL;
        DYPSwizzleOne(cls,
                      @selector(dataTaskWithRequest:completionHandler:),
                      @selector(dyp_dataTaskWithRequest:completionHandler:),
                      &origIMP);
        if (origIMP && !gOrig_dataTask_completion) {
            gOrig_dataTask_completion = origIMP;
        }
    }

    // uploadTask
    Method uploadM = class_getInstanceMethod(cls, @selector(uploadTaskWithRequest:fromData:completionHandler:));
    if (uploadM) {
        IMP origIMP = NULL;
        DYPSwizzleOne(cls,
                      @selector(uploadTaskWithRequest:fromData:completionHandler:),
                      @selector(dyp_uploadTaskWithRequest:fromData:completionHandler:),
                      &origIMP);
        if (origIMP && !gOrig_uploadTask_completion) {
            gOrig_uploadTask_completion = origIMP;
        }
    }
}

static void DYPInstallSwizzle(void) {
    gSwizzledClasses = [[NSMutableSet alloc] init];
    gTaskMap = [[NSMutableDictionary alloc] init];

    // 1) 遍历所有 NSURLSession 子类
    Class sessionCls = NSClassFromString(@"NSURLSession");
    if (sessionCls) {
        unsigned int count = 0;
        Class *classList = objc_copyClassList(&count);
        for (unsigned int i = 0; i < count; i++) {
            Class cls = classList[i];
            Class superCls = class_getSuperclass(cls);
            // 找 NSURLSession 的直接子类 + 孙子类（递归判断）
            Class tmp = cls;
            while (tmp) {
                if (tmp == sessionCls) {
                    DYPSwizzleSessionSubclass(cls);
                    break;
                }
                tmp = class_getSuperclass(tmp);
            }
        }
        free(classList);
    }

    // 2) Hook NSURLSessionTask -resume（兜底，覆盖所有 task 类型）
    Class taskCls = NSClassFromString(@"NSURLSessionTask");
    if (taskCls) {
        DYPSwizzleOne(taskCls,
                      @selector(resume),
                      @selector(dyp_resume),
                      &gOrig_taskResume);
    }

    NSLog(@"[DYProbe] swizzle done: %d NSURLSession subclasses, taskResume=%p",
          gDiagSubclassCount, gOrig_taskResume);
}

#pragma mark - Entry

__attribute__((constructor))
static void DYProbeInit(void) {
    pthread_mutex_init(&gLock, NULL);
    gRequests    = [[NSMutableArray alloc] init];
    gCompletions = [[NSMutableArray alloc] init];
    gOutputPath  = DYPDocPath();

    // 立刻装 swizzle，避免错过早期请求
    DYPInstallSwizzle();

    // 等 1.5 秒确保 libswiftMetal.dylib 加载完后再抓 BSS
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        DYPCapturePluginInfo();
        DYPFlushDump();
        NSLog(@"[DYProbe] BSS captured, output=%@", gOutputPath);
    });

    // NSURLSession 私有子类可能 lazy 加载，多次重跑 install 抓最新子类
    for (int sec = 0; sec <= 10; sec++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(sec * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            DYPInstallSwizzle();
            DYPFlushDump();
        });
    }

    // 周期性 flush + 重 install（防止用户拷文件时还没写盘）
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        while (1) {
            [NSThread sleepForTimeInterval:5.0];
            // 每 5 秒重新 install 一次（覆盖晚期 lazy 子类）
            dispatch_async(dispatch_get_main_queue(), ^{
                DYPInstallSwizzle();
            });
            DYPFlushDump();
        }
    });

    NSLog(@"[DYProbe] swizzle installed at constructor, output=%@", gOutputPath);
}
