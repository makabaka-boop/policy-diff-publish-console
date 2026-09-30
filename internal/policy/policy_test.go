package policy

import "testing"

// TestDiamondInheritance 验证菱形继承：superanalyst 应通过 analyst、auditor
// 两条路径（以及它们共同的父角色 reader）获得权限。
func TestDiamondInheritance(t *testing.T) {
	_, published := SeedPolicy()

	eff := EffectiveRoles(published, "superanalyst")
	want := map[string]bool{
		"superanalyst": true,
		"analyst":      true,
		"auditor":      true,
		"reader":       true,
	}
	if len(eff) != len(want) {
		t.Fatalf("生效角色数 = %d (%v), 期望 %d", len(eff), eff, len(want))
	}
	for _, id := range eff {
		if !want[id] {
			t.Errorf("生效角色集合中出现意外角色 %q: %v", id, eff)
		}
	}

	cases := []struct {
		role, res, act string
		effect         string
		winning        string
	}{
		// 直接父角色 analyst 的规则。
		{"superanalyst", "dataset", "write", EffectAllow, "p-analyst-dataset-write"},
		// 直接父角色 auditor 的规则。
		{"superanalyst", "auditlog", "read", EffectAllow, "p-auditor-log-read"},
		// 经由菱形两条路径共同到达 reader 的规则。
		{"superanalyst", "dataset", "read", EffectAllow, "p-reader-dataset-read"},
		{"analyst", "dataset", "read", EffectAllow, "p-reader-dataset-read"},
		// 未命中任何规则 -> 默认 deny。
		{"reader", "auditlog", "delete", EffectDeny, ""},
		{"auditor", "dataset", "export", EffectDeny, ""},
	}
	for _, c := range cases {
		d := Decide(published, c.role, c.res, c.act)
		if d.Effect != c.effect {
			t.Errorf("Decide(%s,%s,%s) effect = %s, 期望 %s", c.role, c.res, c.act, d.Effect, c.effect)
		}
		if c.winning == "" {
			if d.Evidence.Reason != ReasonDefaultDeny {
				t.Errorf("Decide(%s,%s,%s) reason = %s, 期望 default_deny", c.role, c.res, c.act, d.Evidence.Reason)
			}
			if d.Evidence.WinningRule != nil {
				t.Errorf("Decide(%s,%s,%s) 不应有获胜规则", c.role, c.res, c.act)
			}
			continue
		}
		if d.Evidence.WinningRule == nil || d.Evidence.WinningRule.RuleID != c.winning {
			got := ""
			if d.Evidence.WinningRule != nil {
				got = d.Evidence.WinningRule.RuleID
			}
			t.Errorf("Decide(%s,%s,%s) winning = %q, 期望 %q", c.role, c.res, c.act, got, c.winning)
		}
		// 继承命中必须标注来源父角色。
		if d.Evidence.WinningRule != nil && c.role == "superanalyst" &&
			c.winning == "p-reader-dataset-read" && d.Evidence.WinningRule.InheritedFrom != "reader" {
			t.Errorf("继承证据来源 = %q, 期望 reader", d.Evidence.WinningRule.InheritedFrom)
		}
	}
}

// TestSamePriorityDenyWins 验证同优先级 deny 胜出，且两条规则都留在证据里。
func TestSamePriorityDenyWins(t *testing.T) {
	p := &Policy{
		Roles:     []Role{{ID: "r"}},
		Resources: []string{"doc"},
		Actions:   []string{"view"},
		Rules: []Rule{
			{ID: "allow-1", Role: "r", Resource: "doc", Action: "view", Effect: EffectAllow, Priority: 10},
			{ID: "deny-1", Role: Wildcard, Resource: "doc", Action: "view", Effect: EffectDeny, Priority: 10},
		},
	}
	d := Decide(p, "r", "doc", "view")
	if d.Effect != EffectDeny {
		t.Fatalf("同优先级冲突效果 = %s, 期望 deny", d.Effect)
	}
	if d.Evidence.WinningRule == nil || d.Evidence.WinningRule.RuleID != "deny-1" {
		t.Fatalf("获胜规则应为 deny-1")
	}
	if len(d.Evidence.MatchedRules) != 2 {
		t.Fatalf("匹配规则数 = %d, 期望 2", len(d.Evidence.MatchedRules))
	}
	if d.Evidence.MatchedRules[0].RuleID != "deny-1" || d.Evidence.MatchedRules[1].RuleID != "allow-1" {
		t.Errorf("证据排序错误: %s, %s", d.Evidence.MatchedRules[0].RuleID, d.Evidence.MatchedRules[1].RuleID)
	}

	// 不同优先级时，高优先级 allow 仍然胜出（优先级优先于 deny 偏向）。
	p.Rules[0].Priority = 20
	d = Decide(p, "r", "doc", "view")
	if d.Effect != EffectAllow || d.Evidence.WinningRule.RuleID != "allow-1" {
		t.Fatalf("高优先级 allow 应胜出, 得到 effect=%s", d.Effect)
	}
}

// TestDefaultDeny 验证未命中默认 deny 与通配符匹配。
func TestDefaultDenyAndWildcard(t *testing.T) {
	p := &Policy{
		Roles:     []Role{{ID: "r"}},
		Resources: []string{"doc", "img"},
		Actions:   []string{"view", "edit"},
		Rules: []Rule{
			{ID: "w", Role: "r", Resource: Wildcard, Action: "view", Effect: EffectAllow, Priority: 1},
		},
	}
	if d := Decide(p, "r", "img", "edit"); d.Effect != EffectDeny || d.Evidence.Reason != ReasonDefaultDeny {
		t.Errorf("未命中应默认 deny, 得到 %s/%s", d.Effect, d.Evidence.Reason)
	}
	if d := Decide(p, "r", "doc", "view"); d.Effect != EffectAllow {
		t.Errorf("通配资源应命中 allow, 得到 %s", d.Effect)
	}
	if got := DecideAll(p); len(got) != 1*2*2 {
		t.Errorf("穷举条目数 = %d, 期望 4", len(got))
	}
}

// TestSeedPreview 验证种子草稿相对已发布版本产生预期的新增允许/拒绝及证据。
func TestSeedPreview(t *testing.T) {
	draft, published := SeedPolicy()
	pv := BuildPreview(draft, published, 1, 1)

	// 新增允许：report:export 对 4 个角色（通配 allow）；
	// dataset:export 上 analyst 的 p10 allow 压过通配 p5 deny，
	// 因此 analyst 与经由菱形继承它的 superanalyst 翻转为 allow，
	// reader/auditor 仅命中 deny 不翻转。
	allowKeys := map[string]bool{}
	for _, c := range pv.NewAllows {
		allowKeys[key(c.Role, c.Resource, c.Action)] = true
		if c.DraftEffect != EffectAllow || c.BaselineEffect != EffectDeny {
			t.Errorf("新增允许方向错误: %+v", c)
		}
		if c.DraftEvidence.WinningRule == nil {
			t.Errorf("新增允许缺少草稿获胜规则证据")
		}
	}
	for _, role := range []string{"reader", "analyst", "auditor", "superanalyst"} {
		if !allowKeys[key(role, "report", "export")] {
			t.Errorf("缺少新增允许 %s:report:export", role)
		}
	}
	for _, role := range []string{"analyst", "superanalyst"} {
		if !allowKeys[key(role, "dataset", "export")] {
			t.Errorf("缺少新增允许 %s:dataset:export（高优先级特定 allow 应压过通配 deny）", role)
		}
	}
	for _, role := range []string{"reader", "auditor"} {
		if allowKeys[key(role, "dataset", "export")] {
			t.Errorf("%s:dataset:export 不应翻转：仅命中通配 deny", role)
		}
	}

	// 新增拒绝：dataset:read 被同优先级通配 deny 翻转（deny 同优先级胜出），
	// 影响全部 4 个角色。
	if len(pv.NewDenies) != 4 {
		t.Fatalf("新增拒绝数 = %d, 期望 4", len(pv.NewDenies))
	}
	for _, c := range pv.NewDenies {
		if c.Resource != "dataset" || c.Action != "read" || c.DraftEffect != EffectDeny {
			t.Errorf("意外的新增拒绝: %s:%s:%s -> %s", c.Role, c.Resource, c.Action, c.DraftEffect)
		}
		if c.DraftEvidence.WinningRule == nil || c.DraftEvidence.WinningRule.RuleID != "d-dataset-read-deny" {
			t.Errorf("新增拒绝的获胜规则证据错误")
		}
		// 同优先级冲突的证据必须同时包含 deny 与基线 allow 两条命中规则。
		if len(c.DraftEvidence.MatchedRules) < 2 {
			t.Errorf("%s:dataset:read 的证据应同时包含 allow 与 deny 两条规则，实际 %d 条",
				c.Role, len(c.DraftEvidence.MatchedRules))
		}
		if c.BaselineEvidence.WinningRule == nil {
			t.Errorf("基线 allow 侧缺少获胜规则证据（应说明翻转前状态）")
		}
	}

	if pv.Total != 4*3*4 {
		t.Errorf("穷举总数 = %d, 期望 48", pv.Total)
	}
	if pv.Unchanged+len(pv.NewAllows)+len(pv.NewDenies) != pv.Total {
		t.Errorf("计数不平: unchanged=%d allows=%d denies=%d total=%d",
			pv.Unchanged, len(pv.NewAllows), len(pv.NewDenies), pv.Total)
	}
	if len(pv.Digest) != 64 {
		t.Errorf("摘要长度 = %d, 期望 64 位十六进制", len(pv.Digest))
	}
}

// TestDigestDetectsEdits 验证草稿或已发布版本发生任何变化，摘要必然不同，
// 且相同内容与修订号生成相同摘要。
func TestDigestDetectsEdits(t *testing.T) {
	draft, published := SeedPolicy()
	pv1 := BuildPreview(draft, published, 1, 1)
	pv2 := BuildPreview(draft.Clone(), published.Clone(), 1, 1)
	if pv1.Digest != pv2.Digest {
		t.Fatal("相同逻辑内容的摘要必须一致")
	}

	// 修改草稿（模拟规则编辑）。
	edited := draft.Clone()
	edited.Rules[0].Priority = 999
	if BuildPreview(edited, published, 1, 1).Digest == pv1.Digest {
		t.Error("编辑草稿规则后摘要必须变化")
	}
	// 草稿修订号变化（模拟其他客户端已保存）。
	if BuildPreview(draft, published, 2, 1).Digest == pv1.Digest {
		t.Error("草稿修订变化后摘要必须变化")
	}
	// 已发布修订号变化（模拟其他客户端已发布）。
	if BuildPreview(draft, published, 1, 2).Digest == pv1.Digest {
		t.Error("已发布修订变化后摘要必须变化")
	}
	// 发布之后：草稿 == 已发布，应无差异。
	pvNone := BuildPreview(published, published, 2, 2)
	if len(pvNone.NewAllows) != 0 || len(pvNone.NewDenies) != 0 || pvNone.Unchanged != pvNone.Total {
		t.Error("草稿与已发布一致时不应有差异")
	}
}

// TestNewDomainEntriesComparedAsDefaultDeny 验证草稿新增角色/资源/操作时，
// 基线缺失的三元组按默认 deny 参与对比。
func TestNewDomainEntriesComparedAsDefaultDeny(t *testing.T) {
	_, published := SeedPolicy()
	draft := published.Clone()
	draft.Roles = append(draft.Roles, Role{ID: "guest"})
	draft.Rules = append(draft.Rules, Rule{
		ID: "g1", Role: "guest", Resource: "report", Action: "read", Effect: EffectAllow, Priority: 1,
	})
	pv := BuildPreview(draft, published, 2, 1)
	found := false
	for _, c := range pv.NewAllows {
		if c.Role == "guest" && c.Resource == "report" && c.Action == "read" {
			found = true
			if c.BaselineEvidence.Reason != ReasonDefaultDeny {
				t.Errorf("基线缺失条目应按 default_deny 对比")
			}
		}
	}
	if !found {
		t.Error("新增角色的 allow 未出现在新增允许中")
	}
}

// TestValidate 覆盖数量上限、环、自环、未知父角色、重复 ID、非法效果。
func TestValidate(t *testing.T) {
	base := func() *Policy {
		d, p := SeedPolicy()
		_ = d
		return p.Clone()
	}

	if err := Validate(base()); err != nil {
		t.Errorf("种子策略应合法: %v", err)
	}

	tooManyRoles := base()
	for i := 0; i < MaxRoles; i++ {
		tooManyRoles.Roles = append(tooManyRoles.Roles, Role{ID: "x"})
	}
	if err := Validate(tooManyRoles); err == nil {
		t.Error("超过角色上限应报错")
	}

	cyclic := base()
	cyclic.Roles = []Role{
		{ID: "a", Parents: []string{"b"}},
		{ID: "b", Parents: []string{"c"}},
		{ID: "c", Parents: []string{"a"}},
	}
	if err := Validate(cyclic); err == nil {
		t.Error("继承环应报错")
	}

	selfLoop := base()
	selfLoop.Roles = []Role{{ID: "a", Parents: []string{"a"}}}
	if err := Validate(selfLoop); err == nil {
		t.Error("自继承应报错")
	}

	unknownParent := base()
	unknownParent.Roles = []Role{{ID: "a", Parents: []string{"ghost"}}}
	if err := Validate(unknownParent); err == nil {
		t.Error("未知父角色应报错")
	}

	badEffect := base()
	badEffect.Rules = append(badEffect.Rules, Rule{
		ID: "bad", Role: "reader", Resource: "report", Action: "read", Effect: "maybe", Priority: 1,
	})
	if err := Validate(badEffect); err == nil {
		t.Error("非法效果应报错")
	}

	dupRule := base()
	dupRule.Rules = append(dupRule.Rules, dupRule.Rules[0])
	if err := Validate(dupRule); err == nil {
		t.Error("重复规则 ID 应报错")
	}

	unknownRef := base()
	unknownRef.Rules[0].Role = "nobody"
	if err := Validate(unknownRef); err == nil {
		t.Error("规则引用未知角色应报错")
	}
}
