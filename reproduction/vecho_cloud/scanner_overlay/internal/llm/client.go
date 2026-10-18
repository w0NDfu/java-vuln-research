package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Client struct {
	BaseURL        string
	APIKey         string
	Model          string
	HTTPClient     *http.Client
	DiagnosticPath string
	AttemptTimeout time.Duration

	mu    sync.Mutex
	usage Usage
}

type Usage struct {
	PromptTokens          int64 `json:"prompt_tokens,omitempty"`
	CompletionTokens      int64 `json:"completion_tokens,omitempty"`
	TotalTokens           int64 `json:"total_tokens,omitempty"`
	PromptCacheHitTokens  int64 `json:"prompt_cache_hit_tokens,omitempty"`
	PromptCacheMissTokens int64 `json:"prompt_cache_miss_tokens,omitempty"`
	ReasoningTokens       int64 `json:"reasoning_tokens,omitempty"`
}

type ChatResult struct {
	Content      string `json:"content"`
	Usage        Usage  `json:"usage,omitempty"`
	FinishReason string `json:"finish_reason,omitempty"`
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Usage Usage `json:"usage,omitempty"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type,omitempty"`
	} `json:"error,omitempty"`
}

func (u *Usage) UnmarshalJSON(data []byte) error {
	type plain Usage
	value := struct {
		*plain
		CompletionDetails struct {
			Reasoning int64 `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
		PromptDetails struct {
			Cached int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	}{plain: (*plain)(u)}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if u.ReasoningTokens == 0 {
		u.ReasoningTokens = value.CompletionDetails.Reasoning
	}
	if u.PromptCacheHitTokens == 0 {
		u.PromptCacheHitTokens = value.PromptDetails.Cached
	}
	return nil
}

type CallDiagnostic struct {
	Time           time.Time           `json:"time"`
	Model          string              `json:"model"`
	ElapsedMS      int64               `json:"elapsed_ms"`
	Attempts       int                 `json:"attempts"`
	HTTPStatus     int                 `json:"http_status,omitempty"`
	FinishReason   string              `json:"finish_reason,omitempty"`
	ErrorClass     string              `json:"error_class,omitempty"`
	Usage          Usage               `json:"usage,omitempty"`
	UsageKnown     bool                `json:"usage_known"`
	UsageScope     string              `json:"usage_scope"`
	AttemptDetails []AttemptDiagnostic `json:"attempt_details,omitempty"`
}

type AttemptDiagnostic struct {
	Attempt    int    `json:"attempt"`
	ElapsedMS  int64  `json:"elapsed_ms"`
	HTTPStatus int    `json:"http_status,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
}

func (c *Client) diagnostic(d CallDiagnostic) {
	if c.DiagnosticPath == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := json.Marshal(d)
	if err != nil {
		return
	}
	if err = os.MkdirAll(filepath.Dir(c.DiagnosticPath), 0700); err != nil {
		return
	}
	f, err := os.OpenFile(c.DiagnosticPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

func (c *Client) Chat(ctx context.Context, messages []Message) (string, error) {
	result, err := c.ChatWithUsage(ctx, messages)
	if err != nil {
		return "", err
	}
	return result.Content, nil
}

func (c *Client) ChatWithUsage(ctx context.Context, messages []Message) (output ChatResult, callErr error) {
	started := time.Now()
	d := CallDiagnostic{Time: started.UTC(), Model: c.Model, UsageScope: "final response only; earlier failed attempts may have unreported billed usage"}
	defer func() {
		d.ElapsedMS = time.Since(started).Milliseconds()
		d.FinishReason = output.FinishReason
		d.Usage = output.Usage
		if callErr != nil {
			d.ErrorClass = "request_failed"
			if errors.Is(callErr, context.DeadlineExceeded) {
				d.ErrorClass = "timeout"
			} else if errors.Is(callErr, context.Canceled) {
				d.ErrorClass = "canceled"
			}
		}
		c.diagnostic(d)
	}()
	if strings.TrimSpace(c.APIKey) == "" {
		return ChatResult{}, fmt.Errorf("missing API key")
	}
	httpClient := c.httpClient()
	attemptTimeout := c.AttemptTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = 180 * time.Second
	}
	// Each attempt gets its own deadline; caller cancellation still bounds all
	// attempts. Three attempts and bounded backoff cap the logical operation.
	operationCtx, cancelOperation := context.WithTimeout(ctx, 3*attemptTimeout+3*time.Second)
	defer cancelOperation()
	ctx = operationCtx
	body, err := json.Marshal(chatRequest{Model: c.Model, Messages: messages, Temperature: 0.1})
	if err != nil {
		return ChatResult{}, err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return ChatResult{}, err
		}
		d.Attempts++
		attemptStarted := time.Now()
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, attemptTimeout)
		req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, c.BaseURL, bytes.NewReader(body))
		if err != nil {
			cancelAttempt()
			return ChatResult{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		resp, err := httpClient.Do(req)
		var data []byte
		if err == nil {
			data, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		ad := AttemptDiagnostic{Attempt: attempt + 1, ElapsedMS: time.Since(attemptStarted).Milliseconds()}
		if resp != nil {
			ad.HTTPStatus = resp.StatusCode
		}
		if err != nil {
			ad.ErrorClass = "transport"
			if errors.Is(err, context.DeadlineExceeded) {
				ad.ErrorClass = "timeout"
			} else if errors.Is(err, context.Canceled) {
				ad.ErrorClass = "canceled"
			}
		}
		d.AttemptDetails = append(d.AttemptDetails, ad)
		cancelAttempt()
		if err != nil {
			lastErr = err
		} else {
			d.HTTPStatus = resp.StatusCode
			if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
				lastErr = fmt.Errorf("llm status %d", resp.StatusCode)
			} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return ChatResult{}, fmt.Errorf("llm status %d", resp.StatusCode)
			} else {
				var decoded chatResponse
				if err := json.Unmarshal(data, &decoded); err != nil {
					return ChatResult{}, err
				}
				if decoded.Error != nil {
					return ChatResult{}, fmt.Errorf("llm provider error: %s", decoded.Error.Type)
				}
				if len(decoded.Choices) == 0 {
					return ChatResult{}, fmt.Errorf("llm returned no choices")
				}
				c.addUsage(decoded.Usage)
				var usageEnvelope map[string]json.RawMessage
				if json.Unmarshal(data, &usageEnvelope) == nil {
					raw, ok := usageEnvelope["usage"]
					d.UsageKnown = ok && string(raw) != "null"
				}
				result := ChatResult{Content: decoded.Choices[0].Message.Content, Usage: decoded.Usage, FinishReason: decoded.Choices[0].FinishReason}
				if result.FinishReason == "length" {
					return result, fmt.Errorf("LLM response truncated (finish_reason=length)")
				}
				if strings.TrimSpace(result.Content) == "" {
					return result, fmt.Errorf("LLM returned empty content (finish_reason=%s)", result.FinishReason)
				}
				return result, nil
			}
		}
		if attempt == 2 {
			break
		}
		select {
		case <-ctx.Done():
			return ChatResult{}, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Second):
		}
	}
	return ChatResult{}, lastErr
}

func (c *Client) Usage() Usage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.usage
}

func (c *Client) httpClient() *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HTTPClient == nil {
		// The per-call context owns the deadline; a shorter client timeout can
		// cancel long model generations and waste the remaining budget on retries.
		c.HTTPClient = &http.Client{}
	}
	return c.HTTPClient
}

func (c *Client) addUsage(usage Usage) {
	if usage.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.usage.Add(usage)
}

func (u *Usage) Add(other Usage) {
	u.PromptTokens += other.PromptTokens
	u.CompletionTokens += other.CompletionTokens
	u.TotalTokens += other.TotalTokens
	u.PromptCacheHitTokens += other.PromptCacheHitTokens
	u.PromptCacheMissTokens += other.PromptCacheMissTokens
	u.ReasoningTokens += other.ReasoningTokens
}

func (u Usage) IsZero() bool {
	return u.PromptTokens == 0 &&
		u.CompletionTokens == 0 &&
		u.TotalTokens == 0 &&
		u.PromptCacheHitTokens == 0 &&
		u.PromptCacheMissTokens == 0 &&
		u.ReasoningTokens == 0
}

func trimForError(data []byte) string {
	s := strings.TrimSpace(string(data))
	if len(s) > 500 {
		return s[:500] + "..."
	}
	return s
}
