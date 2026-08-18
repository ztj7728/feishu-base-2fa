# 飞书多维表格 2FA / TOTP 插件

一个纯前端的飞书多维表格侧边栏插件：读取当前选中记录里的 `2FA Secret` 字段，在浏览器本地生成 TOTP 验证码。

## 表格要求

至少创建一个文本字段：

- `2FA Secret`：填写 Base32 Secret，或完整的 `otpauth://totp/...` 地址。

可选字段（用于插件顶部展示）：`网站` / `平台` / `名称` / `服务`，以及 `账号` / `邮箱` / `用户名` / `用户`。

## GitHub Pages

仓库自带 `.github/workflows/deploy-pages.yml`。在仓库 Settings > Pages 中把 Source 设为 GitHub Actions，提交到 main 后会自动构建并部署。

## 安全提醒

不要把真实 2FA Secret 写进本仓库源码。Secret 应只放在飞书多维表格的受控字段里；插件在当前浏览器中读取并计算，不会主动上传 Secret。
