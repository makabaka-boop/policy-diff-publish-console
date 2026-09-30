package policy

import (
	"fmt"
	"strings"
)

// Validate 校验一份策略是否满足有限域约束：
// 数量上限、标识符合法且唯一、父角色存在、继承图无环、规则取值合法。
func Validate(p *Policy) error {
	var errs []string

	if len(p.Roles) > MaxRoles {
		errs = append(errs, fmt.Sprintf("角色数量 %d 超过上限 %d", len(p.Roles), MaxRoles))
	}
	if len(p.Resources) > MaxResources {
		errs = append(errs, fmt.Sprintf("资源类别数量 %d 超过上限 %d", len(p.Resources), MaxResources))
	}
	if len(p.Actions) > MaxActions {
		errs = append(errs, fmt.Sprintf("操作数量 %d 超过上限 %d", len(p.Actions), MaxActions))
	}
	if len(p.Rules) > MaxRules {
		errs = append(errs, fmt.Sprintf("规则数量 %d 超过上限 %d", len(p.Rules), MaxRules))
	}

	roleIDs := map[string]bool{}
	for _, r := range p.Roles {
		if strings.TrimSpace(r.ID) == "" {
			errs = append(errs, "存在没有 ID 的角色")
			continue
		}
		if r.ID == Wildcard {
			errs = append(errs, "角色 ID 不能保留为通配符 *")
		}
		if roleIDs[r.ID] {
			errs = append(errs, fmt.Sprintf("角色 ID 重复: %q", r.ID))
		}
		roleIDs[r.ID] = true
		if len(r.Parents) > MaxParents {
			errs = append(errs, fmt.Sprintf("角色 %q 的父角色数量 %d 超过上限 %d", r.ID, len(r.Parents), MaxParents))
		}
	}

	for _, r := range p.Roles {
		seen := map[string]bool{}
		for _, parent := range r.Parents {
			if parent == r.ID {
				errs = append(errs, fmt.Sprintf("角色 %q 不能继承自身", r.ID))
				continue
			}
			if !roleIDs[parent] {
				errs = append(errs, fmt.Sprintf("角色 %q 引用了不存在的父角色 %q", r.ID, parent))
				continue
			}
			if seen[parent] {
				errs = append(errs, fmt.Sprintf("角色 %q 的父角色 %q 重复", r.ID, parent))
			}
			seen[parent] = true
		}
	}

	if cycle := findCycle(p.Roles); cycle != "" {
		errs = append(errs, "角色继承图存在环: "+cycle)
	}

	resSet := map[string]bool{}
	for _, res := range p.Resources {
		if strings.TrimSpace(res) == "" {
			errs = append(errs, "存在空的资源类别")
			continue
		}
		if resSet[res] {
			errs = append(errs, fmt.Sprintf("资源类别重复: %q", res))
		}
		resSet[res] = true
	}
	actSet := map[string]bool{}
	for _, act := range p.Actions {
		if strings.TrimSpace(act) == "" {
			errs = append(errs, "存在空的操作")
			continue
		}
		if actSet[act] {
			errs = append(errs, fmt.Sprintf("操作重复: %q", act))
		}
		actSet[act] = true
	}

	ruleIDs := map[string]bool{}
	for i, rule := range p.Rules {
		label := rule.ID
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		if strings.TrimSpace(rule.ID) == "" {
			errs = append(errs, fmt.Sprintf("规则 %q 缺少 ID", label))
		} else if ruleIDs[rule.ID] {
			errs = append(errs, fmt.Sprintf("规则 ID 重复: %q", rule.ID))
		}
		ruleIDs[rule.ID] = true

		if rule.Role != Wildcard && !roleIDs[rule.Role] {
			errs = append(errs, fmt.Sprintf("规则 %q 引用了不存在的角色 %q", label, rule.Role))
		}
		if rule.Resource != Wildcard && !resSet[rule.Resource] {
			errs = append(errs, fmt.Sprintf("规则 %q 引用了不存在的资源类别 %q", label, rule.Resource))
		}
		if rule.Action != Wildcard && !actSet[rule.Action] {
			errs = append(errs, fmt.Sprintf("规则 %q 引用了不存在的操作 %q", label, rule.Action))
		}
		if rule.Effect != EffectAllow && rule.Effect != EffectDeny {
			errs = append(errs, fmt.Sprintf("规则 %q 的效果 %q 非法（仅允许 allow/deny）", label, rule.Effect))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "；"))
	}
	return nil
}

// findCycle 在父角色图中做 DFS 三色标记，返回一条环的文字描述；无环返回 ""。
func findCycle(roles []Role) string {
	byID := map[string]Role{}
	for _, r := range roles {
		byID[r.ID] = r
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var stack []string

	var dfs func(id string) []string
	dfs = func(id string) []string {
		color[id] = gray
		stack = append(stack, id)
		for _, parent := range byID[id].Parents {
			if _, ok := byID[parent]; !ok {
				continue // 未知父角色已由其它校验报错
			}
			switch color[parent] {
			case gray:
				// 从 parent 在栈中的位置到栈顶构成一条环。
				for i, n := range stack {
					if n == parent {
						return append(append([]string{}, stack[i:]...), parent)
					}
				}
			case white:
				if cyc := dfs(parent); cyc != nil {
					return cyc
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[id] = black
		return nil
	}

	// 固定遍历顺序，错误信息稳定。
	ids := make([]string, 0, len(roles))
	for _, r := range roles {
		ids = append(ids, r.ID)
	}
	for _, id := range ids {
		if color[id] == white {
			if cyc := dfs(id); cyc != nil {
				return strings.Join(cyc, " -> ")
			}
		}
	}
	return ""
}

// Clone 深拷贝一份策略，避免调用方在发布后继续修改共享底层切片。
func (p *Policy) Clone() *Policy {
	cp := &Policy{
		Roles:     make([]Role, len(p.Roles)),
		Resources: append([]string(nil), p.Resources...),
		Actions:   append([]string(nil), p.Actions...),
		Rules:     append([]Rule(nil), p.Rules...),
	}
	for i, r := range p.Roles {
		cp.Roles[i] = Role{
			ID:      r.ID,
			Name:    r.Name,
			Parents: append([]string(nil), r.Parents...),
		}
	}
	return cp
}
