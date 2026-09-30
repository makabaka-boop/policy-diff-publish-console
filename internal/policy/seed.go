package policy

// SeedPolicy 返回一份演示用初始策略。
//
// 已发布版本包含一个角色继承菱形（边的方向为“子角色继承父角色”）：
//
//	analyst       auditor
//	    \         /
//	     \       /
//	  superanalyst      （顶部：同时继承 analyst 与 auditor）
//	    \       /
//	     \     /
//	      reader         （底部基座角色）
//
// 即：analyst、auditor 继承 reader；superanalyst 同时继承 analyst、auditor，
// 因而通过两条路径获得 reader 的权限。
//
// 草稿相对已发布多了四条规则，用来直接演示：
//   - 菱形继承：superanalyst 经由 analyst/auditor 取得各自权限；
//   - 同优先级冲突：dataset:read 基线经 reader 授予 allow（p10），草稿新增
//     同优先级通配 deny（p10），deny 胜出并把 4 个角色全部翻成“新增拒绝”，
//     草稿证据里同时保留 allow 与 deny 两条命中规则；
//   - 优先级裁决：dataset:export 上 analyst 的 allow(p10) 压过通配 deny(p5)，
//     analyst 与 superanalyst 得到“新增允许”，reader/auditor 仍拒绝；
//   - report:export 对所有角色“新增允许”。
func SeedPolicy() (draft, published *Policy) {
	published = &Policy{
		Roles: []Role{
			{ID: "reader", Name: "读者"},
			{ID: "analyst", Name: "分析员", Parents: []string{"reader"}},
			{ID: "auditor", Name: "审计员", Parents: []string{"reader"}},
			{ID: "superanalyst", Name: "高级分析员", Parents: []string{"analyst", "auditor"}},
		},
		Resources: []string{"report", "dataset", "auditlog"},
		Actions:   []string{"read", "write", "export", "delete"},
		Rules: []Rule{
			{ID: "p-reader-dataset-read", Role: "reader", Resource: "dataset", Action: "read", Effect: EffectAllow, Priority: 10},
			{ID: "p-reader-report-read", Role: "reader", Resource: "report", Action: "read", Effect: EffectAllow, Priority: 10},
			{ID: "p-analyst-dataset-write", Role: "analyst", Resource: "dataset", Action: "write", Effect: EffectAllow, Priority: 20},
			{ID: "p-auditor-log-read", Role: "auditor", Resource: "auditlog", Action: "read", Effect: EffectAllow, Priority: 20},
		},
	}

	draft = published.Clone()
	draft.Rules = append(draft.Rules,
		Rule{ID: "d-report-export-allow", Role: Wildcard, Resource: "report", Action: "export", Effect: EffectAllow, Priority: 15},
		Rule{ID: "d-dataset-export-deny", Role: Wildcard, Resource: "dataset", Action: "export", Effect: EffectDeny, Priority: 5},
		Rule{ID: "d-dataset-export-allow", Role: "analyst", Resource: "dataset", Action: "export", Effect: EffectAllow, Priority: 10},
		Rule{ID: "d-dataset-read-deny", Role: Wildcard, Resource: "dataset", Action: "read", Effect: EffectDeny, Priority: 10},
	)
	return draft, published
}
