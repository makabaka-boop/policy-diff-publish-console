// Package server 提供模拟访问策略的 HTTP API。
// 所有状态保存在内存中并由一把互斥锁保护；这不是真实鉴权入口。
package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"policylab/internal/policy"
)

// 错误码（放在响应体 error.code 中，前端可据此给出中文提示）。
const (
	CodeInvalidBody     = "invalid_body"
	CodeInvalidPolicy   = "invalid_policy"
	CodeRevisionStale   = "revision_stale"
	CodePreviewMismatch = "preview_mismatch"
)

// ErrConflict 表示请求因修订号或预览摘要不匹配而被拒绝（HTTP 409）。
var ErrConflict = errors.New("conflict")

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Limits 回显有限域的边界约束，供前端做表单校验。
type Limits struct {
	MaxRoles     int `json:"maxRoles"`
	MaxResources int `json:"maxResources"`
	MaxActions   int `json:"maxActions"`
	MaxRules     int `json:"maxRules"`
	MaxParents   int `json:"maxParents"`
}

// State 是 GET /api/state 的响应。
type State struct {
	Draft             policy.Policy `json:"draft"`
	Published         policy.Policy `json:"published"`
	DraftRevision     int           `json:"draftRevision"`
	PublishedRevision int           `json:"publishedRevision"`
	Limits            Limits        `json:"limits"`
}

// SaveDraftRequest 保存编辑草稿；必须携带客户端读取时的 draftRevision。
type SaveDraftRequest struct {
	BaseDraftRevision int           `json:"baseDraftRevision"`
	Policy            policy.Policy `json:"policy"`
}

// PublishRequest 发布时必须同时携带三个版本凭证：
// 草稿修订、已发布修订，以及发布前预览返回的摘要。
// 任一方在预览之后发生变化，或摘要对不上，都会被拒绝。
type PublishRequest struct {
	DraftRevision     int    `json:"draftRevision"`
	PublishedRevision int    `json:"publishedRevision"`
	PreviewDigest     string `json:"previewDigest"`
}

// PublishResponse 是发布成功后的新状态片段。
type PublishResponse struct {
	Published         policy.Policy `json:"published"`
	Draft             policy.Policy `json:"draft"`
	DraftRevision     int           `json:"draftRevision"`
	PublishedRevision int           `json:"publishedRevision"`
}

type store struct {
	mu                sync.Mutex
	draft             *policy.Policy
	published         *policy.Policy
	draftRevision     int
	publishedRevision int
}

func newStore(draft, published *policy.Policy) *store {
	return &store{
		draft:             draft,
		published:         published,
		draftRevision:     1,
		publishedRevision: 1,
	}
}

func (s *store) snapshot() State {
	return State{
		Draft:             *s.draft.Clone(),
		Published:         *s.published.Clone(),
		DraftRevision:     s.draftRevision,
		PublishedRevision: s.publishedRevision,
		Limits: Limits{
			MaxRoles: policy.MaxRoles, MaxResources: policy.MaxResources,
			MaxActions: policy.MaxActions, MaxRules: policy.MaxRules,
			MaxParents: policy.MaxParents,
		},
	}
}

// saveDraft 在修订号匹配时整体替换草稿，并推进草稿修订。
func (s *store) saveDraft(baseRev int, p *policy.Policy) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if baseRev != s.draftRevision {
		return State{}, ErrConflict
	}
	s.draft = p.Clone()
	s.draftRevision++
	return s.snapshot(), nil
}

// publish 校验三重凭证后发布：
//  1. 草稿修订必须仍等于预览时的修订；
//  2. 已发布修订必须仍等于预览时的修订；
//  3. 用当前两份策略重新穷举计算的预览摘要必须与客户端带回的一致。
//
// 三者共同保证：发布的正是“刚刚预览过的那个草稿 × 已发布组合”，
// 不可能发布未经预览的混合版本。
func (s *store) publish(req PublishRequest) (PublishResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.DraftRevision != s.draftRevision || req.PublishedRevision != s.publishedRevision {
		return PublishResponse{}, ErrConflict
	}
	currentDigest := policy.BuildPreview(s.draft, s.published, s.draftRevision, s.publishedRevision).Digest
	if req.PreviewDigest == "" || req.PreviewDigest != currentDigest {
		return PublishResponse{}, ErrConflict
	}
	s.published = s.draft.Clone()
	s.publishedRevision++
	return PublishResponse{
		Published:         *s.published.Clone(),
		Draft:             *s.draft.Clone(),
		DraftRevision:     s.draftRevision,
		PublishedRevision: s.publishedRevision,
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Code: code, Message: msg})
}

// decodeJSON 解析请求体；空 body 视为空对象（允许无载荷的 POST）。
func decodeJSON(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

// Server 持有 HTTP 处理器与内存状态。
type Server struct {
	store *store
	mux   *http.ServeMux
}

// New 使用给定的初始策略构建服务。
func New(draft, published *policy.Policy) *Server {
	s := &Server{store: newStore(draft, published)}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /api/state", s.handleState)
	s.mux.HandleFunc("PUT /api/draft", s.handleSaveDraft)
	s.mux.HandleFunc("POST /api/preview", s.handlePreview)
	s.mux.HandleFunc("POST /api/publish", s.handlePublish)
	return s
}

// NewDefault 使用内置演示策略构建服务。
func NewDefault() *Server {
	draft, published := policy.SeedPolicy()
	return New(draft, published)
}

// Handler 返回带模拟声明响应头的根处理器。
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-PolicyLab", "simulation-only; not a real authz endpoint")
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	writeJSON(w, http.StatusOK, s.store.snapshot())
}

func (s *Server) handleSaveDraft(w http.ResponseWriter, r *http.Request) {
	var req SaveDraftRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidBody, "请求体不是合法 JSON: "+err.Error())
		return
	}
	if err := policy.Validate(&req.Policy); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidPolicy, err.Error())
		return
	}
	st, err := s.store.saveDraft(req.BaseDraftRevision, &req.Policy)
	if err != nil {
		writeError(w, http.StatusConflict, CodeRevisionStale,
			"草稿已被其他客户端修改，请刷新后重新编辑（之前的预览已过期）")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// previewRequest 允许客户端在不保存草稿的前提下，对“候选草稿”做预览；
// 但摘要中会绑定当前服务器上的草稿/已发布修订，发布时必须仍与之一致。
type previewRequest struct {
	// Policy 可选：传入则对该候选策略做预览（仍须通过校验）；
	// 省略则预览服务器当前草稿。
	Policy *policy.Policy `json:"policy,omitempty"`
	// BaseDraftRevision 当传入候选策略时必须提供；
	// 仅用于确认客户端看到的草稿修订没有过期。
	BaseDraftRevision int `json:"baseDraftRevision,omitempty"`
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	var req previewRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidBody, "请求体不是合法 JSON: "+err.Error())
		return
	}

	s.store.mu.Lock()
	draft := s.store.draft.Clone()
	baseline := s.store.published.Clone()
	draftRev := s.store.draftRevision
	publishedRev := s.store.publishedRevision
	s.store.mu.Unlock()

	if req.Policy != nil {
		if err := policy.Validate(req.Policy); err != nil {
			writeError(w, http.StatusBadRequest, CodeInvalidPolicy, err.Error())
			return
		}
		if req.BaseDraftRevision != draftRev {
			writeError(w, http.StatusConflict, CodeRevisionStale,
				"草稿已被其他客户端修改，请刷新后重新生成预览")
			return
		}
		draft = req.Policy.Clone()
	}

	writeJSON(w, http.StatusOK, policy.BuildPreview(draft, baseline, draftRev, publishedRev))
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	var req PublishRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidBody, "请求体不是合法 JSON: "+err.Error())
		return
	}
	resp, err := s.store.publish(req)
	if err != nil {
		writeError(w, http.StatusConflict, CodePreviewMismatch,
			"发布被拒绝：草稿、已发布版本或预览摘要已变化，不允许发布未经预览的混合版本，请重新预览")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
