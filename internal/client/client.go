// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	lark "github.com/larksuite/oapi-sdk-go/v3"
	larkcore "github.com/larksuite/oapi-sdk-go/v3/core"

	"github.com/larksuite/cli/internal/core"
	"github.com/larksuite/cli/internal/credential"
	"github.com/larksuite/cli/internal/output"
	"github.com/larksuite/cli/internal/util"
)

// RawApiRequest describes a raw API request.
type RawApiRequest struct {
	Method    string
	URL       string
	Params    map[string]interface{}
	Data      interface{}
	As        core.Identity
	ExtraOpts []larkcore.RequestOptionFunc // additional SDK request options (e.g. security headers)
}

// APIClient wraps lark.Client for all Lark Open API calls.
type APIClient struct {
	Config     *core.CliConfig
	SDK        *lark.Client // All Lark API calls go through SDK
	HTTP       *http.Client // Only for non-Lark API (OAuth, MCP, etc.)
	ErrOut     io.Writer    // debug/progress output
	Credential *credential.CredentialProvider
}

// buildAuthRequiredError 构造"需要用户授权"错误。
// 文案直接写明给 Agent 的行为指令：发链接给用户、本轮立即结束、禁止重试。
// 这样无需修改任何 prompt，Agent 读到错误就知道该怎么做。
func buildAuthRequiredError(reason string) error {
	authURL := os.Getenv("LARKSUITE_CLI_AUTH_REDIRECT_URL")
	if authURL == "" {
		authURL = "请运行 `lark-cli auth login` 完成授权"
	}
	return fmt.Errorf(
		"AUTH_REQUIRED: %s\n\n"+
			"⚠️ 这不是技术错误，是用户尚未完成飞书授权。\n"+
			"授权链接: %s\n\n"+
			"【给 Agent 的指令 - 必须严格遵守】\n"+
			"1. 立即用 channel_send 把上面的授权链接发给当前用户，说明需要重新授权\n"+
			"2. 发完链接后【本轮任务必须立即结束】，不要再调用任何工具\n"+
			"3. 【绝对禁止】重试当前命令或其他 lark-cli 命令——用户没点链接前，重试 100 次都是同样的错\n"+
			"4. 等用户下一次主动发消息时，再继续未完成的工作",
		reason, authURL,
	)
}

func (c *APIClient) resolveAccessToken(ctx context.Context, as core.Identity) (string, error) {
	// External token injection via env var — caller manages token lifecycle.
	// 任一外部注入方式被设置时，都作为唯一来源，失败即报错，不 fallback 到 keychain。
	// Priority: env var > token URL > token file > credential provider chain (keychain).
	if !as.IsBot() {
		if envToken := os.Getenv("LARKSUITE_CLI_USER_ACCESS_TOKEN"); envToken != "" {
			return envToken, nil
		}
		if tokenURL := os.Getenv("LARKSUITE_CLI_USER_ACCESS_TOKEN_URL"); tokenURL != "" {
			return c.fetchTokenFromURL(ctx, tokenURL)
		}
		if tokenFile := os.Getenv("LARKSUITE_CLI_USER_ACCESS_TOKEN_FILE"); tokenFile != "" {
			fileBytes, err := os.ReadFile(tokenFile)
			if err != nil {
				return "", buildAuthRequiredError(fmt.Sprintf("token file not found: %s", tokenFile))
			}
			fileToken := strings.TrimSpace(string(fileBytes))
			if fileToken == "" {
				return "", buildAuthRequiredError(fmt.Sprintf("token file is empty: %s", tokenFile))
			}
			return fileToken, nil
		}
	}

	// 无外部注入 → 走 credential provider chain（keychain / config 文件）
	result, err := c.Credential.ResolveToken(ctx, credential.NewTokenSpec(as, c.Config.AppID))
	if err != nil {
		var unavailableErr *credential.TokenUnavailableError
		if errors.As(err, &unavailableErr) {
			return "", buildAuthRequiredError(fmt.Sprintf("no access token available for %s", as))
		}
		return "", err
	}
	if result.Token == "" {
		return "", buildAuthRequiredError(fmt.Sprintf("no access token available for %s", as))
	}
	return result.Token, nil
}

// fetchTokenFromURL 从 Anya server 的内部端点动态获取最新的 user_access_token。
// server 侧会自动 refresh 快过期的 token，所以调用方无需关心 token 生命周期。
func (c *APIClient) fetchTokenFromURL(ctx context.Context, tokenURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		// 构造请求失败是编程错误，不是授权问题
		return "", fmt.Errorf("token URL request build failed: %v", err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// 连接失败是基础设施问题，不是授权问题，不要让 Agent 发授权链接
		return "", fmt.Errorf("token URL unreachable (server may be down): %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		// 401 = token 真的过期且无法 refresh → 授权问题
		// 尝试从响应体提取 server 提供的 auth_url，优先于 env 里的默认值
		var authResp struct {
			AuthURL string `json:"auth_url"`
		}
		if json.Unmarshal(body, &authResp) == nil && authResp.AuthURL != "" {
			return "", fmt.Errorf(
				"AUTH_REQUIRED: token URL returned HTTP 401\n\n"+
					"⚠️ 这不是技术错误，是用户尚未完成飞书授权。\n"+
					"授权链接: %s\n\n"+
					"【给 Agent 的指令 - 必须严格遵守】\n"+
					"1. 立即用 channel_send 把上面的授权链接发给当前用户，说明需要重新授权\n"+
					"2. 发完链接后【本轮任务必须立即结束】，不要再调用任何工具\n"+
					"3. 【绝对禁止】重试当前命令或其他 lark-cli 命令——用户没点链接前，重试 100 次都是同样的错\n"+
					"4. 等用户下一次主动发消息时，再继续未完成的工作",
				authResp.AuthURL,
			)
		}
		return "", buildAuthRequiredError(fmt.Sprintf("token URL returned HTTP 401: %s", strings.TrimSpace(string(body))))
	}
	if resp.StatusCode != http.StatusOK {
		// 其他 HTTP 错误（404 instance 不存在、500 server 内部错误等）不是授权问题
		return "", fmt.Errorf("token URL returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("token URL response parse failed: %v", err)
	}
	if result.Token == "" {
		return "", buildAuthRequiredError("token URL returned empty token")
	}
	return result.Token, nil
}

// buildApiReq converts a RawApiRequest into SDK types and collects
// request-specific options (ExtraOpts, URL-based headers).
// Auth is handled separately by DoSDKRequest.
func (c *APIClient) buildApiReq(request RawApiRequest) (*larkcore.ApiReq, []larkcore.RequestOptionFunc) {
	queryParams := make(larkcore.QueryParams)
	for k, v := range request.Params {
		switch val := v.(type) {
		case []string:
			queryParams[k] = val
		case []interface{}:
			for _, item := range val {
				queryParams.Add(k, fmt.Sprintf("%v", item))
			}
		default:
			queryParams.Set(k, fmt.Sprintf("%v", v))
		}
	}

	apiReq := &larkcore.ApiReq{
		HttpMethod:  strings.ToUpper(request.Method),
		ApiPath:     request.URL,
		Body:        request.Data,
		QueryParams: queryParams,
	}

	var opts []larkcore.RequestOptionFunc
	opts = append(opts, request.ExtraOpts...)
	return apiReq, opts
}

// DoSDKRequest resolves auth for the given identity and executes a pre-built SDK request.
// This is the shared auth+execute path used by both DoAPI (generic API calls via RawApiRequest)
// and shortcut RuntimeContext.DoAPI (direct larkcore.ApiReq calls).
func (c *APIClient) DoSDKRequest(ctx context.Context, req *larkcore.ApiReq, as core.Identity, extraOpts ...larkcore.RequestOptionFunc) (*larkcore.ApiResp, error) {
	var opts []larkcore.RequestOptionFunc

	token, err := c.resolveAccessToken(ctx, as)
	if err != nil {
		return nil, err
	}
	if as.IsBot() {
		req.SupportedAccessTokenTypes = []larkcore.AccessTokenType{larkcore.AccessTokenTypeTenant}
		opts = append(opts, larkcore.WithTenantAccessToken(token))
	} else {
		req.SupportedAccessTokenTypes = []larkcore.AccessTokenType{larkcore.AccessTokenTypeUser}
		opts = append(opts, larkcore.WithUserAccessToken(token))
	}

	opts = append(opts, extraOpts...)
	return c.SDK.Do(ctx, req, opts...)
}

// DoStream executes a streaming HTTP request against the Lark OpenAPI endpoint.
// Unlike DoSDKRequest (which buffers the full body via the SDK), DoStream returns
// a live *http.Response whose Body is an io.Reader for streaming consumption.
// Auth is resolved via Credential (same as DoSDKRequest). Security headers and
// any extra headers from opts are applied automatically.
// HTTP errors (status >= 400) are handled internally: the body is read (up to 4 KB),
// closed, and returned as an output.ErrNetwork — callers only receive successful responses.
func (c *APIClient) DoStream(ctx context.Context, req *larkcore.ApiReq, as core.Identity, opts ...Option) (*http.Response, error) {
	cfg := buildConfig(opts)

	// Resolve auth
	token, err := c.resolveAccessToken(ctx, as)
	if err != nil {
		return nil, err
	}

	// Build URL
	requestURL, err := buildStreamURL(c.Config.Brand, req)
	if err != nil {
		return nil, err
	}

	// Build body
	bodyReader, contentType, err := buildStreamBody(req.Body)
	if err != nil {
		return nil, err
	}

	// Timeout — use context deadline only; httpClient.Timeout would cut off
	// healthy streaming responses because it includes body read time.
	httpClient := *c.HTTP
	httpClient.Timeout = 0
	cancel := func() {}
	requestCtx := ctx
	if cfg.timeout > 0 {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			requestCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
		}
	}

	// Build request
	httpReq, err := http.NewRequestWithContext(requestCtx, req.HttpMethod, requestURL, bodyReader)
	if err != nil {
		cancel()
		return nil, output.ErrNetwork("stream request failed: %s", err)
	}

	// Apply headers from opts
	for k, vs := range cfg.headers {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}

	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		cancel()
		return nil, output.ErrNetwork("stream request failed: %s", err)
	}
	resp.Body = &cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}

	// Handle HTTP errors internally
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(errBody))
		if msg != "" {
			return nil, output.ErrNetwork("HTTP %d: %s", resp.StatusCode, msg)
		}
		return nil, output.ErrNetwork("HTTP %d", resp.StatusCode)
	}

	return resp, nil
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelOnCloseBody) Close() error {
	err := r.ReadCloser.Close()
	if r.cancel != nil {
		r.cancel()
	}
	return err
}

func buildStreamURL(brand core.LarkBrand, req *larkcore.ApiReq) (string, error) {
	requestURL := req.ApiPath
	if !strings.HasPrefix(requestURL, "http://") && !strings.HasPrefix(requestURL, "https://") {
		var pathSegs []string
		for _, segment := range strings.Split(req.ApiPath, "/") {
			if !strings.HasPrefix(segment, ":") {
				pathSegs = append(pathSegs, segment)
				continue
			}
			pathKey := strings.TrimPrefix(segment, ":")
			pathValue, ok := req.PathParams[pathKey]
			if !ok {
				return "", output.ErrValidation("missing path param %q for %s", pathKey, req.ApiPath)
			}
			if pathValue == "" {
				return "", output.ErrValidation("empty path param %q for %s", pathKey, req.ApiPath)
			}
			pathSegs = append(pathSegs, url.PathEscape(pathValue))
		}
		endpoints := core.ResolveEndpoints(brand)
		requestURL = strings.TrimRight(endpoints.Open, "/") + strings.Join(pathSegs, "/")
	}
	if query := req.QueryParams.Encode(); query != "" {
		requestURL += "?" + query
	}
	return requestURL, nil
}

func buildStreamBody(body interface{}) (io.Reader, string, error) {
	switch typed := body.(type) {
	case nil:
		return nil, "", nil
	case io.Reader:
		return typed, "", nil
	case []byte:
		return bytes.NewReader(typed), "", nil
	case string:
		return strings.NewReader(typed), "text/plain; charset=utf-8", nil
	default:
		payload, err := json.Marshal(typed)
		if err != nil {
			return nil, "", output.Errorf(output.ExitInternal, "api_error", "failed to encode request body: %s", err)
		}
		return bytes.NewReader(payload), "application/json", nil
	}
}

// DoAPI executes a raw Lark SDK request and returns the raw *larkcore.ApiResp.
// Unlike CallAPI which always JSON-decodes, DoAPI returns the raw response — suitable
// for file downloads (pass larkcore.WithFileDownload() via request.ExtraOpts) and
// any endpoint whose Content-Type may not be JSON.
func (c *APIClient) DoAPI(ctx context.Context, request RawApiRequest) (*larkcore.ApiResp, error) {
	apiReq, extraOpts := c.buildApiReq(request)
	return c.DoSDKRequest(ctx, apiReq, request.As, extraOpts...)
}

// CallAPI is a convenience wrapper: DoAPI + ParseJSONResponse.
// Use DoAPI directly when the response may not be JSON (e.g. file downloads).
func (c *APIClient) CallAPI(ctx context.Context, request RawApiRequest) (interface{}, error) {
	resp, err := c.DoAPI(ctx, request)
	if err != nil {
		return nil, err
	}
	return ParseJSONResponse(resp)
}

// paginateLoop runs the core pagination loop. For each successful page (code == 0),
// it calls onResult if non-nil. It always accumulates and returns all raw page results.
func (c *APIClient) paginateLoop(ctx context.Context, request RawApiRequest, opts PaginationOptions, onResult func(interface{})) ([]interface{}, error) {
	var allResults []interface{}
	var pageToken string
	page := 0
	pageDelay := opts.PageDelay
	if pageDelay == 0 {
		pageDelay = 200
	}

	for {
		page++
		params := make(map[string]interface{})
		for k, v := range request.Params {
			params[k] = v
		}
		if pageToken != "" {
			params["page_token"] = pageToken
		}

		fmt.Fprintf(c.ErrOut, "[page %d] fetching...\n", page)
		result, err := c.CallAPI(ctx, RawApiRequest{
			Method:    request.Method,
			URL:       request.URL,
			Params:    params,
			Data:      request.Data,
			As:        request.As,
			ExtraOpts: request.ExtraOpts,
		})
		if err != nil {
			if page == 1 {
				return nil, err
			}
			fmt.Fprintf(c.ErrOut, "[page %d] error, stopping pagination\n", page)
			break
		}

		if resultMap, ok := result.(map[string]interface{}); ok {
			code, _ := util.ToFloat64(resultMap["code"])
			if code != 0 {
				allResults = append(allResults, result)
				if page == 1 {
					return allResults, nil
				}
				fmt.Fprintf(c.ErrOut, "[page %d] API error (code=%.0f), stopping pagination\n", page, code)
				break
			}
		}

		if onResult != nil {
			onResult(result)
		}
		allResults = append(allResults, result)

		pageToken = ""
		if resultMap, ok := result.(map[string]interface{}); ok {
			if data, ok := resultMap["data"].(map[string]interface{}); ok {
				hasMore, _ := data["has_more"].(bool)
				if hasMore {
					if pt, ok := data["page_token"].(string); ok && pt != "" {
						pageToken = pt
					} else if pt, ok := data["next_page_token"].(string); ok && pt != "" {
						pageToken = pt
					}
				}
			}
		}

		if pageToken == "" {
			break
		}

		if opts.PageLimit > 0 && page >= opts.PageLimit {
			fmt.Fprintf(c.ErrOut, "[pagination] reached page limit (%d), stopping. Use --page-all --page-limit 0 to fetch all pages.\n", opts.PageLimit)
			break
		}

		if pageDelay > 0 {
			time.Sleep(time.Duration(pageDelay) * time.Millisecond)
		}
	}
	return allResults, nil
}

// PaginateAll fetches all pages and returns a single merged result.
// Use this for formats that need the complete dataset (e.g. JSON).
func (c *APIClient) PaginateAll(ctx context.Context, request RawApiRequest, opts PaginationOptions) (interface{}, error) {
	results, err := c.paginateLoop(ctx, request, opts, nil)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return map[string]interface{}{}, nil
	}
	if len(results) == 1 {
		return results[0], nil
	}
	return mergePagedResults(c.ErrOut, results), nil
}

// StreamPages fetches all pages and streams each page's list items via onItems.
// Returns the last page result (for error checking), whether any list items were found,
// and any network error. Use this for streaming formats (ndjson, table, csv).
func (c *APIClient) StreamPages(ctx context.Context, request RawApiRequest, onItems func([]interface{}), opts PaginationOptions) (result interface{}, hasItems bool, err error) {
	totalItems := 0
	results, loopErr := c.paginateLoop(ctx, request, opts, func(r interface{}) {
		resultMap, ok := r.(map[string]interface{})
		if !ok {
			return
		}
		data, ok := resultMap["data"].(map[string]interface{})
		if !ok {
			return
		}
		arrayField := output.FindArrayField(data)
		if arrayField == "" {
			return
		}
		items, ok := data[arrayField].([]interface{})
		if !ok {
			return
		}
		totalItems += len(items)
		onItems(items)
		hasItems = true
	})
	if loopErr != nil {
		return nil, false, loopErr
	}

	if hasItems {
		fmt.Fprintf(c.ErrOut, "[pagination] streamed %d pages, %d total items\n", len(results), totalItems)
	}

	if len(results) > 0 {
		return results[len(results)-1], hasItems, nil
	}
	return map[string]interface{}{"code": 0, "msg": "success", "data": map[string]interface{}{}}, false, nil
}

// CheckLarkResponse inspects a Lark API response for business-level errors (non-zero code).
// Uses type assertion instead of interface{} == nil to satisfy interface_nil_check lint.
// Returns nil if result is not a map, map is nil, or code is 0.
func CheckLarkResponse(result interface{}) error {
	resultMap, ok := result.(map[string]interface{})
	if !ok || resultMap == nil {
		return nil
	}
	code, _ := util.ToFloat64(resultMap["code"])
	if code == 0 {
		return nil
	}
	larkCode := int(code)
	msg, _ := resultMap["msg"].(string)
	return output.ErrAPI(larkCode, fmt.Sprintf("API error: [%d] %s", larkCode, msg), resultMap["error"])
}
