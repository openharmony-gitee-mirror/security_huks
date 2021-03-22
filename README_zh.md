# HUKS组件<a name="ZH-CN_TOPIC_0000001133264329"></a>

-   [简介](#section19960105154710)
-   [目录](#section11146193674920)
-   [相关仓](#section1554141575016)

## 简介<a name="section19960105154710"></a>

HUKS是通用密钥管理服务，向应用提供KeyStore及Crypto接口API，包括密钥管理及加解密等功能。

HUKS模块整体分为北向接口，南向适配层，以及核心的功能模块：

1.  HUKS 北向接口：提供统一的对外API，用C语言实现，保持所有设备一致，主要包括密钥生成API、加解密API等；
2.  HUKS HAL层：屏蔽底层硬件和OS的差异，定义HUKS需要的统一底层API，主要包括平台算法库、IO和LOG等；
3.  HUKS Core Module：依赖HAL层，提供核心功能，如加解密、签名验签、密钥存储等。

## 目录<a name="section11146193674920"></a>

```
base/security
├── huks
│   ├── frameworks
│   │   └── huks_lite  HUKS代码实现
│   └── interfaces
│       └── innerkits
│           └── huks_lite  HUKS提供接口
```

## 相关仓<a name="section1554141575016"></a>

[安全子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E5%AE%89%E5%85%A8%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

**security\_huks**

[security\_deviceauth](https://gitee.com/openharmony/security_deviceauth/blob/master/README_zh.md)

