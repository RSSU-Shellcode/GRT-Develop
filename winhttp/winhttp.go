package winhttp

// Request is the defined HTTP request in win_http.h.
type Request struct {
	URL            string // https://user:pass@www.example.com/test.txt
	Headers        string // split by "\r\n"
	UserAgent      string // default User-Agent
	ProxyURL       string // http://www.example.com:8080
	ProxyUser      string // proxy server username
	ProxyPass      string // proxy server password
	ConnectTimeout uint32 // milliseconds, default is 60s
	SendTimeout    uint32 // milliseconds, default is 600s
	ReceiveTimeout uint32 // milliseconds, default is 600s
	MaxBodySize    uint32 // zero is no limit
	AccessType     uint8  // reference document about WinHttpOpen
	Body           []byte // skip this field value
}

// Response is the defined HTTP response in win_http.h.
type Response struct {
	StatusCode int32  // example 200, 404
	Headers    string // split by "\r\n"
	Body       []byte // skip this field value
}
