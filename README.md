# DYProbe Native

原生 ObjC 抓包探针，无 frida 依赖，TrollStore 兼容。

## 用途

抓 `libswiftMetal.dylib` (作者插件) 跟服务器 `106.53.173.140` 之间的 HTTP 请求/响应，
用于反推服务器响应 schema。

## 实现

- `+load`/constructor 挂载 → method swizzle `NSURLSession.dataTaskWithRequest:completionHandler:`
- 命中 `host == 106.53.173.140` → 记录 URL/headers/body + 包装 completion 抓响应
- 同时 dump `libswiftMetal.dylib + 0x1734000` 起 64KB BSS
- 输出到 `/var/mobile/Documents/dyprobe_dump.json`

## 架构

- arm64 thin (cputype=0x0100000c, cpusub=0)
- iOS 14+
- 无 JIT 依赖（不需要 dynamic-codesigning），TrollStore 直接可用

## 编译

GitHub Actions 自动跑 macos-14 + Xcode iOS SDK + ldid 假签名，产出 `libNetSnoop.dylib`。

本地编译（macOS only）：

```bash
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
xcrun --sdk iphoneos clang -arch arm64 -isysroot "$SDK" \
  -mios-version-min=14.0 -fobjc-arc -dynamiclib \
  -install_name @rpath/libNetSnoop.dylib \
  -framework Foundation -framework CoreFoundation \
  -lobjc -O2 DYProbe.m -o libNetSnoop.dylib
ldid -S libNetSnoop.dylib
```

## 使用

1. 用 TrollFools 给 Aweme.app 注入 `libNetSnoop.dylib`
2. 杀抖音重开
3. 进演唱会助手页用一会儿（让心跳跑几轮 + 触发服务器响应）
4. Filza 进 `/var/mobile/Containers/Data/Application/<Aweme-Sandbox-UUID>/Documents/`
   找 `dyprobe_dump.json` 拷出来
5. 发回给开发者
