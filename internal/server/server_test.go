package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"policylab/internal/policy"
)

func newTestServer() (*Server, *policy.Policy, *policy.Policy) {
	draft, published := policy.SeedPolicy()
	return New(draft, published), draft, published
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("响应不是 JSON: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func getState(t *testing.T, h http.Handler) State {
	t.Helper()
	code, body := doJSON(t, h, http.MethodGet, "/api/state", nil)
	if code != http.StatusOK {
		t.Fatalf("GET state = %d", code)
	}
	raw, _ := json.Marshal(body)
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestHappyPathPreviewThenPublish 正常流程：预览 -> 三重凭证发布成功，发布后差异归零。
func TestHappyPathPreviewThenPublish(t *testing.T) {
	srv, _, _ := newTestServer()
	h := srv.Handler()
	st := getState(t, h)

	code, pvRaw := doJSON(t, h, http.MethodPost, "/api/preview", nil)
	if code != http.StatusOK {
		t.Fatalf("preview = %d", code)
	}
	if pvRaw["newAllows"].([]any) == nil {
		t.Fatal("预览缺少 newAllows")
	}

	req := PublishRequest{
		DraftRevision:     st.DraftRevision,
		PublishedRevision: st.PublishedRevision,
		PreviewDigest:     pvRaw["digest"].(string),
	}
	code, body := doJSON(t, h, http.MethodPost, "/api/publish", req)
	if code != http.StatusOK {
		t.Fatalf("publish = %d: %v", code, body)
	}
	if int(body["publishedRevision"].(float64)) != st.PublishedRevision+1 {
		t.Errorf("发布后已发布修订应为 %d", st.PublishedRevision+1)
	}

	// 发布后再预览：草稿 == 已发布，不应再有任何新增允许/拒绝。
	code, after := doJSON(t, h, http.MethodPost, "/api/preview", nil)
	if code != http.StatusOK {
		t.Fatalf("second preview = %d", code)
	}
	if len(after["newAllows"].([]any)) != 0 || len(after["newDenies"].([]any)) != 0 {
		t.Errorf("发布后不应再有差异: allows=%v denies=%v", after["newAllows"], after["newDenies"])
	}
}

// TestStalePreviewAfterRuleEdit 规则编辑后旧预览必须失效：
// 先预览，再保存编辑过的草稿（修订推进），用旧的三重凭证发布应被 409 拒绝。
func TestStalePreviewAfterRuleEdit(t *testing.T) {
	srv, draft, _ := newTestServer()
	h := srv.Handler()
	st := getState(t, h)

	_, pvRaw := doJSON(t, h, http.MethodPost, "/api/preview", nil)
	staleDigest := pvRaw["digest"].(string)

	// 模拟在预览之后编辑规则：提升一条规则的优先级并保存草稿。
	edited := draft.Clone()
	edited.Rules[0].Priority += 5
	code, body := doJSON(t, h, http.MethodPut, "/api/draft", SaveDraftRequest{
		BaseDraftRevision: st.DraftRevision,
		Policy:            *edited,
	})
	if code != http.StatusOK {
		t.Fatalf("save draft = %d: %v", code, body)
	}

	// 用旧预览凭证发布：草稿修订已变化，必须拒绝。
	code, body = doJSON(t, h, http.MethodPost, "/api/publish", PublishRequest{
		DraftRevision:     st.DraftRevision,
		PublishedRevision: st.PublishedRevision,
		PreviewDigest:     staleDigest,
	})
	if code != http.StatusConflict {
		t.Fatalf("过期预览发布应返回 409, 实际 %d: %v", code, body)
	}
	if body["code"] != CodePreviewMismatch {
		t.Errorf("错误码 = %v, 期望 preview_mismatch", body["code"])
	}
}

// TestTamperedDigestRejected 草稿与已发布修订都没变、但客户端伪造/截断摘要，
// 同样必须拒绝（不能发布未经真实预览的内容）。
func TestTamperedDigestRejected(t *testing.T) {
	srv, _, _ := newTestServer()
	h := srv.Handler()
	st := getState(t, h)

	code, body := doJSON(t, h, http.MethodPost, "/api/publish", PublishRequest{
		DraftRevision:     st.DraftRevision,
		PublishedRevision: st.PublishedRevision,
		PreviewDigest:     "deadbeef",
	})
	if code != http.StatusConflict {
		t.Fatalf("伪造摘要发布应 409, 实际 %d: %v", code, body)
	}

	code, body = doJSON(t, h, http.MethodPost, "/api/publish", PublishRequest{
		DraftRevision:     st.DraftRevision,
		PublishedRevision: st.PublishedRevision,
		PreviewDigest:     "",
	})
	if code != http.StatusConflict {
		t.Fatalf("空摘要发布应 409, 实际 %d", code)
	}
}

// TestConcurrentClientsPublish 两个客户端基于同一份状态各自预览并竞争发布：
// 只有一个能成功，另一个因已发布修订推进（旧预览过期）被拒绝。
func TestConcurrentClientsPublish(t *testing.T) {
	srv, _, _ := newTestServer()
	h := srv.Handler()
	st := getState(t, h)

	// 客户端 A、B 看到完全相同的状态，各自独立预览，拿到相同摘要。
	_, pvA := doJSON(t, h, http.MethodPost, "/api/preview", nil)
	_, pvB := doJSON(t, h, http.MethodPost, "/api/preview", nil)
	tokenA := PublishRequest{st.DraftRevision, st.PublishedRevision, pvA["digest"].(string)}
	tokenB := PublishRequest{st.DraftRevision, st.PublishedRevision, pvB["digest"].(string)}
	if tokenA.PreviewDigest != tokenB.PreviewDigest {
		t.Fatal("相同状态的预览摘要必须一致")
	}

	// A 抢先发布成功。
	code, body := doJSON(t, h, http.MethodPost, "/api/publish", tokenA)
	if code != http.StatusOK {
		t.Fatalf("客户端 A 发布应成功, 实际 %d: %v", code, body)
	}

	// B 持旧的三重凭证发布：已发布修订已被 A 推进，必须失败。
	code, body = doJSON(t, h, http.MethodPost, "/api/publish", tokenB)
	if code != http.StatusConflict {
		t.Fatalf("客户端 B 的竞争发布应 409, 实际 %d: %v", code, body)
	}

	// B 刷新、重新预览后可以再次发布（此时草稿==已发布，差异为空，但仍是一次合法发布）。
	st2 := getState(t, h)
	_, pvB2 := doJSON(t, h, http.MethodPost, "/api/preview", nil)
	code, _ = doJSON(t, h, http.MethodPost, "/api/publish", PublishRequest{
		DraftRevision:     st2.DraftRevision,
		PublishedRevision: st2.PublishedRevision,
		PreviewDigest:     pvB2["digest"].(string),
	})
	if code != http.StatusOK {
		t.Fatalf("B 刷新并重新预览后发布应成功, 实际 %d", code)
	}
}

// TestConcurrentClientsOneEditsOnePublishes 竞争场景变体：
// A 在编辑草稿（保存推进 draftRevision），B 不能用旧预览发布。
func TestConcurrentClientsOneEditsOnePublishes(t *testing.T) {
	srv, draft, _ := newTestServer()
	h := srv.Handler()
	st := getState(t, h)

	// B 先做预览。
	_, pvB := doJSON(t, h, http.MethodPost, "/api/preview", nil)

	// A 保存一次编辑（哪怕内容相同），草稿修订推进。
	code, _ := doJSON(t, h, http.MethodPut, "/api/draft", SaveDraftRequest{
		BaseDraftRevision: st.DraftRevision,
		Policy:            *draft.Clone(),
	})
	if code != http.StatusOK {
		t.Fatalf("A 保存草稿失败: %d", code)
	}

	// B 用旧 draftRevision + 旧摘要发布，必须被拒绝。
	code, body := doJSON(t, h, http.MethodPost, "/api/publish", PublishRequest{
		DraftRevision:     st.DraftRevision,
		PublishedRevision: st.PublishedRevision,
		PreviewDigest:     pvB["digest"].(string),
	})
	if code != http.StatusConflict {
		t.Fatalf("B 持过期预览发布应 409, 实际 %d: %v", code, body)
	}
}

// TestSaveDraftConflicts 两个客户端顺序保存同一基修订，第二个必须被拒。
func TestSaveDraftConflicts(t *testing.T) {
	srv, draft, _ := newTestServer()
	h := srv.Handler()
	st := getState(t, h)

	first := draft.Clone()
	second := draft.Clone()
	second.Rules[0].Priority = 1

	code, _ := doJSON(t, h, http.MethodPut, "/api/draft", SaveDraftRequest{
		BaseDraftRevision: st.DraftRevision, Policy: *first,
	})
	if code != http.StatusOK {
		t.Fatalf("第一次保存应成功: %d", code)
	}
	code, body := doJSON(t, h, http.MethodPut, "/api/draft", SaveDraftRequest{
		BaseDraftRevision: st.DraftRevision, Policy: *second,
	})
	if code != http.StatusConflict || body["code"] != CodeRevisionStale {
		t.Fatalf("基于过期修订保存应 409 revision_stale, 实际 %d: %v", code, body)
	}
}

// TestSaveDraftValidation 非法策略不能进草稿（环、超上限、坏引用等由 policy 层校验）。
func TestSaveDraftValidation(t *testing.T) {
	srv, draft, _ := newTestServer()
	h := srv.Handler()
	st := getState(t, h)

	bad := draft.Clone()
	bad.Roles = append(bad.Roles, policy.Role{ID: "a", Parents: []string{"b"}}, policy.Role{ID: "b", Parents: []string{"a"}})
	code, body := doJSON(t, h, http.MethodPut, "/api/draft", SaveDraftRequest{
		BaseDraftRevision: st.DraftRevision, Policy: *bad,
	})
	if code != http.StatusBadRequest || body["code"] != CodeInvalidPolicy {
		t.Fatalf("含环策略应 400 invalid_policy, 实际 %d: %v", code, body)
	}

	bad = draft.Clone()
	bad.Actions = []string{"a1", "a2", "a3", "a4", "a5", "a6", "a7"}
	code, _ = doJSON(t, h, http.MethodPut, "/api/draft", SaveDraftRequest{
		BaseDraftRevision: st.DraftRevision, Policy: *bad,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("超过 6 种操作应 400, 实际 %d", code)
	}
}

// TestPreviewCandidateRevisionGuard 候选草稿预览也要带当前草稿修订，
// 防止基于过期编辑生成预览。
func TestPreviewCandidateRevisionGuard(t *testing.T) {
	srv, draft, _ := newTestServer()
	h := srv.Handler()
	st := getState(t, h)

	candidate := draft.Clone()
	candidate.Rules = candidate.Rules[:2]

	code, body := doJSON(t, h, http.MethodPost, "/api/preview", previewRequest{
		Policy: candidate, BaseDraftRevision: st.DraftRevision,
	})
	if code != http.StatusOK {
		t.Fatalf("候选预览应成功: %d: %v", code, body)
	}

	// A 先推进草稿修订。
	code, _ = doJSON(t, h, http.MethodPut, "/api/draft", SaveDraftRequest{
		BaseDraftRevision: st.DraftRevision, Policy: *draft.Clone(),
	})
	if code != http.StatusOK {
		t.Fatalf("推进草稿失败: %d", code)
	}

	// B 仍拿旧基修订做候选预览，应 409。
	code, body = doJSON(t, h, http.MethodPost, "/api/preview", previewRequest{
		Policy: candidate, BaseDraftRevision: st.DraftRevision,
	})
	if code != http.StatusConflict {
		t.Fatalf("过期候选预览应 409, 实际 %d: %v", code, body)
	}
}

// TestSimulatedHeader 所有 API 响应带模拟声明头。
func TestSimulatedHeader(t *testing.T) {
	srv, _, _ := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if got := rec.Header().Get("X-PolicyLab"); got == "" {
		t.Error("缺少 X-PolicyLab 模拟声明响应头")
	}
}
