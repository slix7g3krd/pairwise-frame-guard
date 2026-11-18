# pairwise-frame-guard

后台管理页嵌入第三方组件后，点击劫持防护就形同虚设：`X-Frame-Options` 只在部分路由设置；值写成 `ALLOW-FROM`，现代浏览器直接忽略；`SAMEORIGIN` 和 CSP `frame-ancestors` 冲突时取了宽松的那个；CSP 里 `frame-ancestors *` 放开所有站点；错误页和登录页完全没有头；多个响应头重复，浏览器取第一个；`frame-ancestors` 用用户输入拼白名单；缺少 `Content-Security-Policy` 时回落到可嵌入；空值和大小写没有归一；代理会删掉安全头。security/frame_guard.py 是核心，tests/test_frame_guard.py 15个红。要修的是：全路由设置；拒绝 ALLOW-FROM；CSP 与 XFO 取严；frame-ancestors 白名单；错误页覆盖；重复头合并；白名单固定；缺头默认拒绝；值归一；代理保留头。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
