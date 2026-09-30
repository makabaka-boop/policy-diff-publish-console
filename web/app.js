/* PolicyLab 前端：两个互相独立的客户端视图，模拟并发编辑/预览/发布。 */
'use strict';

const { createApp } = Vue;

const clone = (v) => JSON.parse(JSON.stringify(v));
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// 单条差异（新增允许 / 新增拒绝）及其命中规则证据。
const ChangeView = {
  props: ['change'],
  template: `
    <div class="triple">
      <span class="t-role">{{ change.role }}</span> :
      <span class="t-res">{{ change.resource }}</span> :
      <span class="t-act">{{ change.action }}</span>
      <span class="arrow">→</span>
      <span :class="change.draftEffect === 'allow' ? 'eff-allow' : 'eff-deny'">
        {{ change.draftEffect === 'allow' ? '允许' : '拒绝' }}
      </span>
    </div>
    <div class="ev">
      <div class="ev-line"><b>草稿证据：</b><evidence :ev="change.draftEvidence"></evidence></div>
      <div class="ev-line muted"><b>发布版原状：</b><evidence :ev="change.baselineEvidence"></evidence></div>
    </div>
  `,
  components: {
    Evidence: {
      props: ['ev'],
      template: `
      <span>
        <template v-if="ev.reason === 'default_deny'">
          未命中任何规则，默认 deny
        </template>
        <template v-else>
          获胜规则
          <rule-tag v-if="ev.winningRule" :r="ev.winningRule"></rule-tag>
          <span v-if="ev.matchedRules.length > 1" class="muted">
            （同域共命中 {{ ev.matchedRules.length }} 条，按优先级降序 / 同级 deny 优先裁决：
            <span v-for="(m, i) in ev.matchedRules" :key="i">
              <rule-tag :r="m" :dim="m.ruleId !== (ev.winningRule && ev.winningRule.ruleId)"></rule-tag><span v-if="i < ev.matchedRules.length - 1">，</span>
            </span>）
          </span>
        </template>
      </span>
      `,
      components: {
        RuleTag: {
          props: ['r', 'dim'],
          template: `
          <code class="rule-tag" :class="{dim: dim}">
            {{ r.ruleId }}
            <span class="muted">[{{ r.role }}/{{ r.resource }}/{{ r.action }} · {{ r.effect }} · p{{ r.priority }}]</span>
            <em v-if="r.inheritedFrom" class="inh">经继承 {{ r.inheritedFrom }} 命中</em>
          </code>
          `,
        },
      },
    },
  },
};

function makeClient(id) {
  return {
    id,
    snapshot: { draft: { roles: [], resources: [], actions: [], rules: [] },
                published: {}, draftRevision: 0, publishedRevision: 0 },
    local: { roles: [], resources: [], actions: [], rules: [] },
    preview: null,
    busy: false,
    loading: false,
    error: '',
    notice: '',
  };
}

createApp({
  components: { ChangeView },
  data() {
    return {
      activeId: 'A',
      clients: [makeClient('A'), makeClient('B')],
      limits: { maxRoles: 8, maxResources: 8, maxActions: 6, maxRules: 256, maxParents: 7 },
    };
  },
  mounted() {
    this.clients.forEach((c) => this.load(c));
  },
  methods: {
    isDirty(c) {
      return !eq(c.local, c.snapshot.draft);
    },
    isStale(c) {
      return !!c.preview && (
        c.preview.draftRevision !== c.snapshot.draftRevision ||
        c.preview.publishedRevision !== c.snapshot.publishedRevision
      );
    },
    canPublish(c) {
      return !!c.preview && !this.isStale(c) && !this.isDirty(c) && !c.busy;
    },
    flash(c, kind, msg) {
      c[kind] = msg;
      if (kind === 'notice') setTimeout(() => (c.notice = ''), 6000);
    },
    async api(c, path, opts) {
      c.busy = true;
      c.error = '';
      try {
        const resp = await fetch(path, {
          headers: { 'Content-Type': 'application/json' },
          ...opts,
        });
        const body = await resp.json().catch(() => ({}));
        return { ok: resp.ok, status: resp.status, body };
      } catch (e) {
        return { ok: false, status: 0, body: { message: String(e) } };
      } finally {
        c.busy = false;
      }
    },
    async load(c) {
      c.loading = true;
      try {
        const r = await fetch('/api/state');
        const st = await r.json();
        this.applyState(c, st);
        this.limits = st.limits;
        c.preview = null;
      } catch (e) {
        this.flash(c, 'error', '载入状态失败：' + e);
      } finally {
        c.loading = false;
      }
    },
    applyState(c, st) {
      c.snapshot = {
        draft: st.draft, published: st.published,
        draftRevision: st.draftRevision, publishedRevision: st.publishedRevision,
      };
      c.local = clone(st.draft);
    },
    addRole(c) {
      c.local.roles.push({ id: '', name: '', parents: [] });
    },
    toggleParent(role, parentId) {
      const i = role.parents.indexOf(parentId);
      if (i >= 0) role.parents.splice(i, 1);
      else role.parents.push(parentId);
    },
    addRule(c) {
      c.local.rules.push({
        id: '', role: '*', resource: '*', action: '*', effect: 'allow', priority: 10,
      });
    },
    removeAt(arr, i) {
      arr.splice(i, 1);
    },
    resetToPublished(c) {
      c.local = clone(c.snapshot.published);
    },
    async saveDraft(c) {
      const base = c.snapshot.draftRevision;
      // 归一化输入：数字框清空时 v-model 会给出空字符串，转成 0 再提交。
      const payload = clone(c.local);
      payload.rules.forEach((r) => {
        if (!Number.isFinite(r.priority)) r.priority = 0;
      });
      const r = await this.api(c, '/api/draft', {
        method: 'PUT',
        body: JSON.stringify({ baseDraftRevision: base, policy: payload }),
      });
      if (!r.ok) {
        if (r.body.code === 'revision_stale') {
          this.flash(c, 'error', '保存被拒（revision_stale）：草稿已被另一个客户端修改，本页编辑基于过期修订，请点“从服务器刷新”后重新编辑。');
        } else {
          this.flash(c, 'error', '草稿未通过校验：' + (r.body.message || r.status));
        }
        return;
      }
      this.applyState(c, r.body);
      c.preview = null;
      this.flash(c, 'notice', `草稿已保存，新草稿修订 #${r.body.draftRevision}。之前的预览已失效。`);
    },
    async preview(c) {
      const r = await this.api(c, '/api/preview', { method: 'POST', body: '{}' });
      if (!r.ok) {
        this.flash(c, 'error', '生成预览失败：' + (r.body.message || r.status));
        return;
      }
      c.preview = r.body;
      this.flash(c, 'notice', '预览已生成：已穷举全部有限决策域并绑定当前两个修订号与摘要。');
    },
    async publish(c) {
      if (!this.canPublish(c)) return;
      const r = await this.api(c, '/api/publish', {
        method: 'POST',
        body: JSON.stringify({
          draftRevision: c.preview.draftRevision,
          publishedRevision: c.preview.publishedRevision,
          previewDigest: c.preview.digest,
        }),
      });
      if (!r.ok) {
        // 发布被拒（另一个客户端抢先发布 / 草稿被改过 / 摘要不符）：刷新服务器状态，
        // 旧预览因修订不再匹配而显示为过期。
        await this.load(c);
        this.flash(c, 'error',
          '发布被拒绝（preview_mismatch）：' + (r.body.message || '') +
          ' 页面已刷新服务器状态，请重新生成预览。');
        return;
      }
      const newPublishedRev = r.body.publishedRevision;
      this.applyState(c, r.body);
      c.preview = null;
      this.flash(c, 'notice', `发布成功，已发布修订推进到 #${newPublishedRev}。`);
    },
  },
}).mount('#app');
