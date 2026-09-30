// Package policy 实现一个“有限域模拟访问策略”引擎。
//
// 它刻意保持为内存中的模拟模型：没有任何真实身份、会话或系统资源，
// 仅用于演示 角色继承 / 规则优先级 / allow-deny 裁决 / 版本对比。
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// 领域上限（题目要求：角色 <= 8、资源类别 <= 8、操作 <= 6）。
const (
	MaxRoles     = 8
	MaxResources = 8
	MaxActions   = 6
	MaxRules     = 256
	MaxParents   = MaxRoles - 1
)

// 效果常量。
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// 命中原因。
const (
	ReasonRuleMatch   = "rule_match"   // 命中显式规则
	ReasonDefaultDeny = "default_deny" // 未命中任何规则，默认拒绝
)

// Wildcard 是规则匹配中使用的通配符。
const Wildcard = "*"

// Role 定义一个角色；Parents 指向它继承的角色，必须构成无环图。
type Role struct {
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	Parents []string `json:"parents,omitempty"`
}

// Rule 是一条策略规则。角色/资源/操作均支持精确值或 "*"。
type Rule struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Effect   string `json:"effect"`
	Priority int    `json:"priority"`
}

// Policy 是某一版本的完整策略快照（整体替换式编辑）。
type Policy struct {
	Roles     []Role   `json:"roles"`
	Resources []string `json:"resources"`
	Actions   []string `json:"actions"`
	Rules     []Rule   `json:"rules"`
}

// RuleRef 是裁决证据中对命中规则的引用。
type RuleRef struct {
	RuleID        string `json:"ruleId"`
	Role          string `json:"role"`
	Resource      string `json:"resource"`
	Action        string `json:"action"`
	Effect        string `json:"effect"`
	Priority      int    `json:"priority"`
	MatchedRole   string `json:"matchedRole"`
	InheritedFrom string `json:"inheritedFrom,omitempty"` // 规则角色经由哪个父角色继承命中
}

// Evidence 解释一个裁决是如何得出的。
type Evidence struct {
	Reason       string    `json:"reason"`
	WinningRule  *RuleRef  `json:"winningRule,omitempty"`
	MatchedRules []RuleRef `json:"matchedRules"` // 按 优先级降序、deny 优先、规则 ID 升序 排列
}

// Decision 是有限域中一个三元组的裁决结果。
type Decision struct {
	Role     string   `json:"role"`
	Resource string   `json:"resource"`
	Action   string   `json:"action"`
	Effect   string   `json:"effect"`
	Evidence Evidence `json:"evidence"`
}

// Change 是草稿相对已发布版本在一个三元组上的差异。
type Change struct {
	Role             string   `json:"role"`
	Resource         string   `json:"resource"`
	Action           string   `json:"action"`
	DraftEffect      string   `json:"draftEffect"`
	BaselineEffect   string   `json:"baselineEffect"`
	DraftEvidence    Evidence `json:"draftEvidence"`
	BaselineEvidence Evidence `json:"baselineEvidence"`
}

// Preview 是一次完整的有限域穷举对比结果。
type Preview struct {
	DraftRevision     int      `json:"draftRevision"`
	PublishedRevision int      `json:"publishedRevision"`
	NewAllows         []Change `json:"newAllows"`
	NewDenies         []Change `json:"newDenies"`
	Unchanged         int      `json:"unchanged"`
	Total             int      `json:"total"`
	// Digest 是对全部差异内容（含修订号）的确定性摘要，发布时必须原样带回。
	Digest string `json:"digest"`
}

// EffectiveRoles 返回某角色在策略中的“生效角色集”（自身 + 全部祖先）。
// 角色不存在时返回 nil。继承图假定已经过 Validate 校验（无环、父角色存在）。
func EffectiveRoles(p *Policy, roleID string) []string {
	byID := make(map[string]Role, len(p.Roles))
	for _, r := range p.Roles {
		byID[r.ID] = r
	}
	if _, ok := byID[roleID]; !ok {
		return nil
	}
	seen := map[string]bool{roleID: true}
	queue := []string{roleID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, parent := range byID[cur].Parents {
			if r, ok := byID[parent]; ok && !seen[parent] {
				seen[parent] = true
				queue = append(queue, r.ID)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func matchField(pattern, value string) bool {
	return pattern == Wildcard || pattern == value
}

// Decide 对 (role, resource, action) 做一次裁决。
// 同优先级 deny 胜过 allow；未命中任何规则则默认 deny。
func Decide(p *Policy, roleID, resource, action string) Decision {
	effective := EffectiveRoles(p, roleID)

	var matched []Rule
	for _, rule := range p.Rules {
		if rule.Role != Wildcard {
			found := false
			for _, er := range effective {
				if er == rule.Role {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if !matchField(rule.Resource, resource) || !matchField(rule.Action, action) {
			continue
		}
		matched = append(matched, rule)
	}

	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].Priority != matched[j].Priority {
			return matched[i].Priority > matched[j].Priority
		}
		if matched[i].Effect != matched[j].Effect {
			return matched[i].Effect == EffectDeny // 同优先级 deny 胜出
		}
		return matched[i].ID < matched[j].ID
	})

	refs := make([]RuleRef, 0, len(matched))
	for _, rule := range matched {
		ref := RuleRef{
			RuleID:      rule.ID,
			Role:        rule.Role,
			Resource:    rule.Resource,
			Action:      rule.Action,
			Effect:      rule.Effect,
			Priority:    rule.Priority,
			MatchedRole: roleID,
		}
		if rule.Role != Wildcard && rule.Role != roleID {
			ref.InheritedFrom = rule.Role
		}
		refs = append(refs, ref)
	}

	d := Decision{
		Role:     roleID,
		Resource: resource,
		Action:   action,
		Effect:   EffectDeny,
		Evidence: Evidence{MatchedRules: refs},
	}
	if len(matched) == 0 {
		d.Evidence.Reason = ReasonDefaultDeny
		return d
	}
	d.Evidence.Reason = ReasonRuleMatch
	win := refs[0]
	d.Evidence.WinningRule = &win
	d.Effect = win.Effect
	return d
}

// DecideAll 穷举 角色 × 资源 × 操作 整个有限决策域。
func DecideAll(p *Policy) []Decision {
	var out []Decision
	for _, role := range p.Roles {
		for _, res := range p.Resources {
			for _, act := range p.Actions {
				out = append(out, Decide(p, role.ID, res, act))
			}
		}
	}
	return out
}

// Diff 穷举草稿与基线（已发布版本）两个有限域，逐三元组对比。
// 只报告发生翻转的条目：基线 deny → 草稿 allow（新增允许），
// 基线 allow → 草稿 deny（新增拒绝）。基线缺失的三元组按默认 deny 处理。
func Diff(draft, baseline *Policy) (newAllows, newDenies []Change, unchanged, total int) {
	baseDecisions := make(map[string]Decision, len(baseline.Roles)*len(baseline.Resources)*len(baseline.Actions))
	for _, d := range DecideAll(baseline) {
		baseDecisions[key(d.Role, d.Resource, d.Action)] = d
	}

	var changes []Change
	for _, d := range DecideAll(draft) {
		k := key(d.Role, d.Resource, d.Action)
		total++
		base, ok := baseDecisions[k]
		if !ok {
			// 基线里没有该角色/资源/操作；按“未命中默认 deny”构造一条基线裁决。
			base = Decision{
				Role: d.Role, Resource: d.Resource, Action: d.Action,
				Effect:   EffectDeny,
				Evidence: Evidence{Reason: ReasonDefaultDeny, MatchedRules: []RuleRef{}},
			}
		}
		if d.Effect == base.Effect {
			unchanged++
			continue
		}
		ch := Change{
			Role:             d.Role,
			Resource:         d.Resource,
			Action:           d.Action,
			DraftEffect:      d.Effect,
			BaselineEffect:   base.Effect,
			DraftEvidence:    d.Evidence,
			BaselineEvidence: base.Evidence,
		}
		changes = append(changes, ch)
	}
	sortChanges(changes)
	for _, ch := range changes {
		if ch.DraftEffect == EffectAllow {
			newAllows = append(newAllows, ch)
		} else {
			newDenies = append(newDenies, ch)
		}
	}
	return newAllows, newDenies, unchanged, total
}

func sortChanges(cs []Change) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Role != cs[j].Role {
			return cs[i].Role < cs[j].Role
		}
		if cs[i].Resource != cs[j].Resource {
			return cs[i].Resource < cs[j].Resource
		}
		return cs[i].Action < cs[j].Action
	})
}

func key(role, resource, action string) string {
	return role + "\x00" + resource + "\x00" + action
}

// canonicalRule / canonicalChange 用于生成与内存布局无关的确定性摘要。
type canonicalRule struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Effect   string `json:"effect"`
	Priority int    `json:"priority"`
}

type canonicalEvidence struct {
	Reason       string          `json:"reason"`
	WinningRule  *canonicalRule  `json:"winningRule,omitempty"`
	MatchedRules []canonicalRule `json:"matchedRules"`
}

type canonicalChange struct {
	Role             string            `json:"role"`
	Resource         string            `json:"resource"`
	Action           string            `json:"action"`
	DraftEffect      string            `json:"draftEffect"`
	BaselineEffect   string            `json:"baselineEffect"`
	DraftEvidence    canonicalEvidence `json:"draftEvidence"`
	BaselineEvidence canonicalEvidence `json:"baselineEvidence"`
}

type canonicalPreview struct {
	DraftRevision     int               `json:"draftRevision"`
	PublishedRevision int               `json:"publishedRevision"`
	NewAllows         []canonicalChange `json:"newAllows"`
	NewDenies         []canonicalChange `json:"newDenies"`
	Unchanged         int               `json:"unchanged"`
	Total             int               `json:"total"`
}

func toCanonicalRule(ref RuleRef) canonicalRule {
	return canonicalRule{
		ID: ref.RuleID, Role: ref.Role, Resource: ref.Resource, Action: ref.Action,
		Effect: ref.Effect, Priority: ref.Priority,
	}
}

func toCanonicalEvidence(e Evidence) canonicalEvidence {
	ce := canonicalEvidence{Reason: e.Reason, MatchedRules: []canonicalRule{}}
	if e.WinningRule != nil {
		r := toCanonicalRule(*e.WinningRule)
		ce.WinningRule = &r
	}
	for _, ref := range e.MatchedRules {
		ce.MatchedRules = append(ce.MatchedRules, toCanonicalRule(ref))
	}
	return ce
}

func toCanonicalChange(ch Change) canonicalChange {
	return canonicalChange{
		Role: ch.Role, Resource: ch.Resource, Action: ch.Action,
		DraftEffect: ch.DraftEffect, BaselineEffect: ch.BaselineEffect,
		DraftEvidence:    toCanonicalEvidence(ch.DraftEvidence),
		BaselineEvidence: toCanonicalEvidence(ch.BaselineEvidence),
	}
}

// canonicalDigest 计算摘要。参数全部为值类型，由调用方传入，
// 因此即便调用之后草稿/已发布版本再被编辑，也不会影响摘要内容。
func canonicalDigest(cp canonicalPreview) string {
	var b strings.Builder
	enc := func(s string) { b.WriteString(s); b.WriteByte(0x1f) }
	enc(itoa(cp.DraftRevision))
	enc(itoa(cp.PublishedRevision))
	writeChanges := func(cs []canonicalChange) {
		enc(itoa(len(cs)))
		for _, c := range cs {
			enc(c.Role)
			enc(c.Resource)
			enc(c.Action)
			enc(c.DraftEffect)
			enc(c.BaselineEffect)
			writeEvidence := func(e canonicalEvidence) {
				enc(e.Reason)
				if e.WinningRule == nil {
					enc("")
				} else {
					enc(e.WinningRule.ID)
				}
				enc(itoa(len(e.MatchedRules)))
				for _, m := range e.MatchedRules {
					enc(m.ID)
				}
			}
			writeEvidence(c.DraftEvidence)
			writeEvidence(c.BaselineEvidence)
		}
	}
	writeChanges(cp.NewAllows)
	writeChanges(cp.NewDenies)
	enc(itoa(cp.Unchanged))
	enc(itoa(cp.Total))
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// BuildPreview 穷举有限域并生成可用于发布校验的预览摘要。
func BuildPreview(draft, baseline *Policy, draftRev, publishedRev int) Preview {
	allows, denies, unchanged, total := Diff(draft, baseline)
	cp := canonicalPreview{
		DraftRevision: draftRev, PublishedRevision: publishedRev,
		Unchanged: unchanged, Total: total,
	}
	pv := Preview{
		DraftRevision: draftRev, PublishedRevision: publishedRev,
		NewAllows: []Change{}, NewDenies: []Change{},
		Unchanged: unchanged, Total: total,
	}
	pv.NewAllows = append(pv.NewAllows, allows...)
	pv.NewDenies = append(pv.NewDenies, denies...)
	for _, c := range allows {
		cp.NewAllows = append(cp.NewAllows, toCanonicalChange(c))
	}
	for _, c := range denies {
		cp.NewDenies = append(cp.NewDenies, toCanonicalChange(c))
	}
	pv.Digest = canonicalDigest(cp)
	return pv
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	var buf [24]byte
	i := len(buf)
	for n != 0 {
		d := n % 10
		if d < 0 {
			d = -d
		}
		i--
		buf[i] = byte('0' + d)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
