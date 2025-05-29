# Network Interface Proxy Server

## 配置檔案 (config.yaml)

```yaml
listen:
  host: "127.0.0.1"
  port: 8080

network:
  interface_ip: "192.168.1.100"  # 指定網卡IP
  dns: "8.8.8.8"                # 可選，DNS伺服器
  retry:                         # 重試機制設定
    max_retries: 3               # 最大重試次數
    retry_delay_seconds: 2       # 重試延遲秒數
    backoff_factor: 2            # 退避係數 (指數退避)

logging:
  level: "error"                 # 日誌等級
  file: "./proxy.log"           # 日誌檔案路徑
```

## 依賴模組

創建 `go.mod` 檔案：

```go
module network-proxy

go 1.20

require gopkg.in/yaml.v3 v3.0.1
```

## 編譯說明

### 安裝依賴
```bash
go mod init network-proxy
go get gopkg.in/yaml.v3
```

### Windows x64 編譯
```bash
# 在Windows上編譯
go build -ldflags "-s -w" -o proxy.exe main.go

# 靜態編譯 (包含所有依賴)
CGO_ENABLED=0 go build -ldflags "-s -w" -o proxy.exe main.go
```

### Linux ARM64 交叉編譯
```bash
# 在Windows/Linux上交叉編譯ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o proxy-arm64 main.go
```

### 所有平台一次編譯
```bash
# Windows x64
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o proxy-windows-x64.exe main.go

# Linux x64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o proxy-linux-x64 main.go

# Linux ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o proxy-linux-arm64 main.go
```

## 使用方法

### 基本使用
```bash
# 使用預設配置檔案 (config.yaml)
./proxy

# 指定配置檔案
./proxy /path/to/config.yaml
```

### Windows Service 安裝
使用 NSSM (Non-Sucking Service Manager):

1. 下載 NSSM: https://nssm.cc/download
2. 安裝服務：
```cmd
nssm install ProxyService "C:\path\to\proxy.exe"
nssm set ProxyService AppDirectory "C:\path\to"
nssm start ProxyService
```

### Linux systemd 服務

創建 `/etc/systemd/system/network-proxy.service`：

```ini
[Unit]
Description=Network Interface Proxy Server
After=network.target

[Service]
Type=simple
User=proxy
WorkingDirectory=/opt/network-proxy
ExecStart=/opt/network-proxy/proxy
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

啟用服務：
```bash
sudo systemctl daemon-reload
sudo systemctl enable network-proxy
sudo systemctl start network-proxy
```

## 重試機制說明

### 網路中斷處理
程序具備智能重試機制，特別針對手機網路不穩定情況：

**重試條件**：
- 連線被拒絕 (Connection refused)
- 網路不可達 (Network unreachable) 
- 連線逾時 (Connection timeout)
- 暫時性錯誤 (Temporary failure)
- 介面不存在 (Interface not found)

**重試策略**：
- **指數退避**：每次重試延遲時間遞增 (2秒 → 4秒 → 8秒)
- **最大重試次數**：可配置，預設3次
- **智能判斷**：只對網路相關錯誤重試，避免無意義重試

**配置範例**：
```yaml
network:
  retry:
    max_retries: 5         # 手機網路建議設高一點
    retry_delay_seconds: 3 # 初始延遲3秒
    backoff_factor: 2      # 每次重試延遲翻倍
```

### 典型使用情境
1. **手機移動時**：自動重試直到網路恢復
2. **訊號微弱**：多次嘗試直到連線成功
3. **網路切換**：從WiFi切到4G/5G時的過渡期

## 配置說明

### 網路介面設定
- `interface_ip`: 指定發出請求使用的網卡IP地址
- 留空時使用系統預設路由

### 日誌設定
- `level`: 目前支援 "error", "info", "debug"
- `file`: 日誌檔案路徑，設為 "stdout" 輸出到控制台

### Chrome 設定
1. 安裝代理切換插件 (如 SwitchyOmega)
2. 設定代理：
   - HTTP代理: 127.0.0.1:8080
   - HTTPS代理: 127.0.0.1:8080
   - SOCKS代理: 不使用

## 測試

### 驗證代理運作
```bash
# 測試HTTP
curl -x http://127.0.0.1:8080 http://httpbin.org/ip

# 測試HTTPS
curl -x http://127.0.0.1:8080 https://httpbin.org/ip
```

### 檢查網卡綁定
使用 `netstat` 或 `ss` 查看連線是否使用指定IP：
```bash
# Linux
ss -tuln | grep :8080

# Windows
netstat -an | findstr :8080
```

## 故障排除

### 常見問題
1. **權限不足**: 某些系統可能需要管理員權限綁定特定網卡
2. **IP不存在**: 確認指定的 interface_ip 確實存在於系統中
3. **防火牆**: 確認防火牆允許代理端口通訊
4. **DNS解析**: 如果指定了DNS但無法解析，會回退到系統DNS

### 日誌查看
```bash
# 實時查看日誌
tail -f proxy.log

# Windows Event Viewer (如果安裝為服務)
eventvwr.msc
```