<template>
  <div class="assets">
    <div class="np-page-header">
      <div>
        <span class="np-page-title">{{ t('assets.title') }}</span>
        <span class="np-page-desc" v-if="items.length">{{ t('assets.assets', { n: items.length }) }}</span>
      </div>
    </div>

    <el-card>
      <!-- 搜索栏 + 排序 -->
      <div class="np-filter-bar">
        <el-input v-model="query" :placeholder="t('assets.searchPlaceholder')" clearable style="width: 260px" @keyup.enter="loadData">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="sortBy" style="width: 160px" @change="loadData">
          <el-option :label="t('assets.sortHostname')" value="hostname" />
          <el-option :label="t('assets.sortPortCount')" value="port_count" />
          <el-option :label="t('assets.sortScanCount')" value="scan_count" />
          <el-option :label="t('assets.sortRiskScore')" value="risk_score" />
        </el-select>
        <el-button type="primary" @click="loadData">{{ t('common.search') }}</el-button>
      </div>

      <!-- 资产表格（全宽，行业惯例布局，支持排序） -->
      <el-table
        :data="pagedItems"
        v-loading="loading"
        size="small"
        stripe
        @row-click="openDetail"
        :default-sort="{ prop: 'risk_score', order: 'descending' }"
        style="width: 100%"
        class="asset-table"
      >
        <!-- IP:端口（主键，左固定） -->
        <el-table-column prop="ip" label="IP:端口" min-width="160" fixed="left" sortable>
          <template #default="{ row }">
            <span class="cell-ip mono">{{ row.ip }}<template v-if="row._preview?.primary">:{{ row._preview.primary.port }}</template></span>
          </template>
        </el-table-column>
        <!-- 域名 -->
        <el-table-column label="域名" min-width="140" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="cell-host mono" v-if="row.hostname && row.hostname !== row.ip">{{ row.hostname }}</span>
            <span v-else class="cell-dash">—</span>
          </template>
        </el-table-column>
        <!-- 站点标题 -->
        <el-table-column label="站点标题" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row._preview?.firstSite?.title" class="cell-title">{{ row._preview.firstSite.title }}</span>
            <span v-else class="cell-dash">—</span>
          </template>
        </el-table-column>
        <!-- 状态码 -->
        <el-table-column label="状态码" width="70" align="center">
          <template #default="{ row }">
            <el-tag v-if="row._preview?.firstSite?.status" :type="statusTagType(row._preview.firstSite.status)" size="small" effect="dark">{{ row._preview.firstSite.status }}</el-tag>
            <span v-else class="cell-dash">—</span>
          </template>
        </el-table-column>
        <!-- Server -->
        <el-table-column label="Server" min-width="110" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row._preview?.firstSite?.server" class="cell-server mono">{{ row._preview.firstSite.server }}</span>
            <span v-else class="cell-dash">—</span>
          </template>
        </el-table-column>
        <!-- 技术栈 -->
        <el-table-column label="技术栈" min-width="200">
          <template #default="{ row }">
            <div class="cell-tech" v-if="row._preview?.firstSite?.tech?.length">
              <el-tooltip
                v-for="(tech, ti) in row._preview.firstSite.tech.slice(0, 4)"
                :key="ti"
                :content="techTooltip(tech)"
                :disabled="!techTooltip(tech)"
                placement="top"
              >
                <el-tag size="small" :type="techTagType(tech)">{{ techLabel(tech) }}</el-tag>
              </el-tooltip>
              <span v-if="row._preview.firstSite.tech.length > 4" class="tech-more">+{{ row._preview.firstSite.tech.length - 4 }}</span>
            </div>
            <span v-else class="cell-dash">—</span>
          </template>
        </el-table-column>
        <!-- 端口 -->
        <el-table-column label="端口" min-width="120">
          <template #default="{ row }">
            <span v-if="row._preview?.ports?.length" class="cell-ports mono">
              {{ row._preview.ports.slice(0, 5).map((p: any) => p.port).join(', ') }}<template v-if="row._preview.ports.length > 5">+{{ row._preview.ports.length - 5 }}</template>
            </span>
            <span v-else class="cell-dash">—</span>
          </template>
        </el-table-column>
        <!-- 扫描次数 -->
        <el-table-column prop="scan_count" label="扫描" width="60" align="center" sortable>
          <template #default="{ row }">{{ row.scan_count }}</template>
        </el-table-column>
        <!-- 漏洞数 -->
        <el-table-column label="漏洞" width="60" align="center" sortable :sort-method="(a: any, b: any) => (a._preview?.vulnCount || 0) - (b._preview?.vulnCount || 0)">
          <template #default="{ row }">
            <span v-if="(row._preview?.vulnCount || 0) > 0" class="cell-vuln">{{ row._preview.vulnCount }}</span>
            <span v-else class="cell-dash">—</span>
          </template>
        </el-table-column>
        <!-- 风险分（右固定） -->
        <el-table-column prop="risk_score" label="风险" width="70" align="center" fixed="right" sortable>
          <template #default="{ row }">
            <span class="cell-risk" :class="riskClass(row.risk_score || 0)">{{ row.risk_score || 0 }}</span>
          </template>
        </el-table-column>

        <!-- 空状态 -->
        <template #empty>
          <div class="np-empty">
            <el-icon :size="36" color="var(--np-text-disabled)"><Grid /></el-icon>
            <p>{{ t('assets.empty') }}</p>
          </div>
        </template>
      </el-table>

      <!-- 分页 -->
      <div class="np-pagination" v-if="items.length">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="perPage"
          :total="items.length"
          :page-sizes="[5, 10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
         
          background
        />
      </div>
    </el-card>

    <!-- 详情弹窗（居中大窗，固定高度，比右侧抽屉更宽，详情一目了然） -->
    <el-dialog
      v-model="drawerVisible"
      :title="drawerTitle"
      width="92vw"
      class="asset-dialog"
      destroy-on-close
    >
      <div v-loading="detailLoading" class="dialog-body">
        <!-- 加载失败 -->
        <div v-if="detailError" class="drawer-error">
          <el-icon :size="22" color="var(--np-danger)"><WarningFilled /></el-icon>
          <span>{{ detailError }}</span>
        </div>

        <template v-else-if="detail">
          <!-- 概览数字条 -->
          <div class="detail-overview">
            <span class="ov-item"><b class="mono">{{ detail.port_count }}</b>{{ t('assets.ports') }}</span>
            <span class="ov-item"><b class="mono">{{ detail.web_count }}</b>{{ t('assets.web') }}</span>
            <span class="ov-item" v-if="detail.vuln_count">
              <b class="mono" style="color:var(--np-danger)">{{ detail.vuln_count }}</b>{{ t('assets.detail.vulns') }}
            </span>
            <span class="ov-item"><b class="mono">{{ detail.scan_count }}</b>{{ t('assets.scans') }}</span>
          </div>

          <!-- Tab 分区 -->
          <el-tabs v-model="detailTab" class="detail-tabs">
            <!-- 漏洞（按分类分组展示） -->
            <el-tab-pane v-if="detail.vulnerabilities?.length" :name="'vulns'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Warning /></el-icon>
                  {{ t('assets.detail.vulns') }}
                  <span class="tab-count danger">{{ detail.vulnerabilities.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <!-- 按分类分组 -->
                <div v-for="group in vulnGroups" :key="group.key" class="vuln-group">
                  <div class="vuln-group-title">
                    <span>{{ group.icon }} {{ group.label }}</span>
                    <el-tag size="small" type="info">{{ group.items.length }}</el-tag>
                  </div>
                  <div v-for="(v, i) in group.items" :key="i" class="vuln-row">
                    <el-tag :type="vulnSeverityType(v.severity)" size="small" effect="dark">{{ v.severity }}</el-tag>
                    <span class="vuln-name">{{ v.name }}</span>
                    <a v-if="v.cve" :href="`https://nvd.nist.gov/vuln/detail/${v.cve}`" target="_blank" rel="noopener" class="mono vuln-cve">{{ v.cve }}</a>
                    <span class="mono cvss" v-if="v.cvss_score">CVSS {{ v.cvss_score }}</span>
                    <el-tag v-if="v.category && group.key === 'other'" size="small" effect="plain">{{ v.category }}</el-tag>
                  </div>
                </div>
              </div>
            </el-tab-pane>

            <!-- 端口服务 -->
            <el-tab-pane v-if="detail.ports?.length" :name="'ports'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Connection /></el-icon>
                  {{ t('assets.detail.portsServices') }}
                  <span class="tab-count">{{ detail.ports.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <el-table :data="detail.ports" size="small" stripe>
                  <el-table-column prop="port" :label="t('table.port')" width="90">
                    <template #default="{ row: p }"><span class="mono">{{ p.port }}/{{ p.proto }}</span></template>
                  </el-table-column>
                  <el-table-column prop="state" :label="t('table.state')" width="80">
                    <template #default="{ row: p }">
                      <el-tag v-if="p.state === 'open'" type="success" size="small">{{ p.state }}</el-tag>
                      <span v-else class="mono">{{ p.state }}</span>
                    </template>
                  </el-table-column>
                  <el-table-column prop="service" :label="t('table.service')" width="100">
                    <template #default="{ row: p }">{{ p.service || '—' }}</template>
                  </el-table-column>
                  <el-table-column prop="product" :label="t('table.product')" min-width="140">
                    <template #default="{ row: p }">
                      <span class="mono">{{ [p.product, p.version].filter(Boolean).join(' ') || '—' }}</span>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
            </el-tab-pane>

            <!-- 协议分层（OSI / TCP-IP 可切换） -->
            <el-tab-pane v-if="detail.ports?.length" :name="'layers'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Histogram /></el-icon>
                  协议分层
                </span>
              </template>
              <div class="tab-content">
                <!-- 模型切换 + 图例 -->
                <div class="layer-toolbar">
                  <el-radio-group v-model="useOSI" size="small">
                    <el-radio-button :value="true">OSI 七层</el-radio-button>
                    <el-radio-button :value="false">TCP/IP 五层</el-radio-button>
                  </el-radio-group>
                  <span class="layer-hint">按开放端口的服务归属到对应协议层，点击服务可展开端口</span>
                </div>

                <!-- 分层栈：从上(7)到下(1)，每层一行 -->
                <div class="layer-stack">
                  <div
                    v-for="layer in layerModel"
                    :key="layer.n"
                    class="layer-row"
                    :class="{ 'layer-active': servicesAt(layer.n).length }"
                  >
                    <!-- 左：层标识 -->
                    <div class="layer-label">
                      <span class="layer-num">L{{ layer.n }}</span>
                      <div class="layer-meta">
                        <div class="layer-name">{{ layer.icon }} {{ layer.name }}</div>
                        <div class="layer-en">{{ layer.en }}</div>
                      </div>
                    </div>
                    <!-- 中：该层的服务/协议 -->
                    <div class="layer-services">
                      <template v-if="servicesAt(layer.n).length">
                        <el-popover
                          v-for="g in servicesAt(layer.n)"
                          :key="g.label"
                          placement="bottom"
                          :width="280"
                          trigger="click"
                        >
                          <template #reference>
                            <span class="svc-chip">
                              {{ g.label }}
                              <b class="mono">{{ g.count }}</b>
                            </span>
                          </template>
                          <div class="svc-pop">
                            <div class="svc-pop-title">{{ g.label }} · {{ g.count }} 个端口</div>
                            <div v-for="(p, i) in g.ports" :key="i" class="svc-pop-port">
                              <span class="mono">{{ p.port }}/{{ p.proto }}</span>
                              <span class="svc-pop-prod">{{ [p.product, p.version].filter(Boolean).join(' ') || '—' }}</span>
                            </div>
                          </div>
                        </el-popover>
                      </template>
                      <span v-else class="layer-empty">—</span>
                    </div>
                  </div>
                </div>

                <!-- 攻击面小结 -->
                <div class="layer-summary">
                  <span class="ls-label">攻击面分布：</span>
                  <span v-for="layer in layerModel" :key="layer.n" class="ls-item" :class="{ zero: !servicesAt(layer.n).length }">
                    L{{ layer.n }} <b>{{ servicesAt(layer.n).reduce((s, g) => s + g.count, 0) }}</b>
                  </span>
                </div>
              </div>
            </el-tab-pane>

            <!-- Web 站点 -->
            <el-tab-pane v-if="detail.web_info?.length" :name="'web'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Monitor /></el-icon>
                  {{ t('assets.detail.webSites') }}
                  <span class="tab-count">{{ detail.web_info.length }}</span>
                </span>
              </template>
              <div class="tab-content web-list">
                <div v-for="(site, i) in detail.web_info" :key="i" class="web-card">
                  <div class="web-head">
                    <a :href="site.url" target="_blank" rel="noopener" class="web-url mono">{{ site.url }}</a>
                    <el-tag v-if="site.status" :type="statusTagType(site.status)" size="small" effect="dark">{{ site.status }}</el-tag>
                  </div>
                  <div class="web-title" v-if="site.title">{{ site.title }}</div>
                  <div class="web-tags" v-if="site.tech?.length">
                    <el-tooltip
                      v-for="(tech, ti) in site.tech"
                      :key="ti"
                      :content="techTooltip(tech)"
                      :disabled="!techTooltip(tech)"
                      placement="top"
                    >
                      <el-tag size="small" :type="techTagType(tech)" class="tech-tag">
                        {{ techLabel(tech) }}
                      </el-tag>
                    </el-tooltip>
                  </div>
                </div>
              </div>
            </el-tab-pane>

            <!-- 敏感路径 -->
            <el-tab-pane v-if="detail.sensitive?.length" :name="'sensitive'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Lock /></el-icon>
                  {{ t('assets.detail.sensitive') }}
                  <span class="tab-count warn">{{ detail.sensitive.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <el-table :data="detail.sensitive" size="small" stripe>
                  <el-table-column prop="path" :label="t('table.path')" min-width="200">
                    <template #default="{ row: s }"><span class="mono">{{ s.path }}</span></template>
                  </el-table-column>
                  <el-table-column prop="severity" :label="t('table.severity')" width="90">
                    <template #default="{ row: s }">
                      <el-tag :type="severityType(s.severity)" size="small">{{ s.severity }}</el-tag>
                    </template>
                  </el-table-column>
                  <el-table-column prop="description" :label="t('table.description')" min-width="160">
                    <template #default="{ row: s }">{{ s.description || '—' }}</template>
                  </el-table-column>
                </el-table>
              </div>
            </el-tab-pane>

            <!-- 技术栈 -->
            <el-tab-pane v-if="detail.tech_stack?.length" :name="'tech'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Cpu /></el-icon>
                  {{ t('assets.detail.techStack') }}
                  <span class="tab-count">{{ detail.tech_stack.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <el-table :data="detail.tech_stack" size="small" stripe class="tech-table">
                  <el-table-column label="名称" min-width="140">
                    <template #default="{ row }">
                      <span class="mono tech-name">{{ row.name }}</span>
                    </template>
                  </el-table-column>
                  <el-table-column label="版本" width="120">
                    <template #default="{ row }">
                      <span v-if="row.version" class="mono tech-version">{{ row.version }}</span>
                      <span v-else class="cell-dash">—</span>
                    </template>
                  </el-table-column>
                  <el-table-column label="类别" width="120">
                    <template #default="{ row }">
                      <el-tag v-if="row.category" :type="techTagType(row)" size="small">{{ row.category }}</el-tag>
                      <span v-else class="cell-dash">—</span>
                    </template>
                  </el-table-column>
                  <el-table-column label="置信度" width="110" align="center">
                    <template #default="{ row }">
                      <span v-if="row.confidence" class="mono" :class="(row.confidence || 0) >= 70 ? 'tech-conf-high' : 'tech-conf-low'">{{ row.confidence }}%</span>
                      <el-tag v-if="row.confidence && (row.confidence || 0) < 70" size="small" type="warning" effect="plain" style="margin-left:4px">推测</el-tag>
                      <span v-if="!row.confidence" class="cell-dash">—</span>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
            </el-tab-pane>

            <!-- Banner -->
            <el-tab-pane v-if="detail.banners?.length" :name="'banners'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Document /></el-icon>
                  {{ t('assets.detail.banners') }}
                  <span class="tab-count">{{ detail.banners.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <div v-for="(b, i) in detail.banners" :key="i" class="banner-row">
                  <span class="mono banner-port">{{ b.port }}</span>
                  <span class="banner-service">{{ b.service || '—' }}</span>
                  <pre class="mono banner-text">{{ b.banner }}</pre>
                </div>
              </div>
            </el-tab-pane>

            <!-- WHOIS / RDAP 注册信息 -->
            <el-tab-pane v-if="detail.whois?.length" :name="'whois'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Document /></el-icon>
                  WHOIS
                  <span class="tab-count">{{ detail.whois.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <div v-for="(w, i) in detail.whois" :key="i" class="whois-block">
                  <div class="whois-head">
                    <el-tag :type="w.type === 'domain' ? 'primary' : 'warning'" size="small">{{ w.type === 'domain' ? '域名' : 'IP' }}</el-tag>
                    <span class="mono whois-target">{{ w.target }}</span>
                    <span class="whois-time" v-if="w.queried_at">{{ formatScanTime(w.queried_at) }}</span>
                  </div>
                  <el-descriptions :column="2" size="small" border class="whois-desc">
                    <el-descriptions-item v-for="(val, key) in flattenWhois(w.data)" :key="key" :label="key">
                      <span class="mono">{{ val }}</span>
                    </el-descriptions-item>
                  </el-descriptions>
                </div>
              </div>
            </el-tab-pane>

            <!-- DNS 记录（A/MX/TXT/NS/CAA + SPF/DMARC） -->
            <el-tab-pane v-if="detail.dns_records?.length" :name="'dns'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Connection /></el-icon>
                  DNS 记录
                  <span class="tab-count">{{ detail.dns_records.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <div v-for="(d, i) in detail.dns_records" :key="i" class="dns-block">
                  <div class="dns-head">
                    <span class="mono dns-target">{{ d.target }}</span>
                  </div>
                  <!-- SPF/DMARC 告警 -->
                  <div v-if="d.data?.warnings?.length" class="dns-warnings">
                    <div v-for="(w, wi) in d.data.warnings" :key="wi" class="dns-warn">⚠ {{ w }}</div>
                  </div>
                  <!-- 各类型记录 -->
                  <el-descriptions :column="1" size="small" border class="dns-desc">
                    <el-descriptions-item v-for="(vals, rtype) in d.data?.records" :key="rtype" :label="rtype">
                      <div v-for="(v, vi) in vals" :key="vi" class="mono dns-val">{{ v }}</div>
                    </el-descriptions-item>
                  </el-descriptions>
                  <!-- 邮件安全配置 -->
                  <div v-if="d.data?.mail_security" class="dns-mailsec">
                    <el-tag :type="d.data.mail_security.spf ? 'success' : 'danger'" size="small">
                      SPF {{ d.data.mail_security.spf ? '✓' : '✗ 缺失' }}
                    </el-tag>
                    <el-tag :type="d.data.mail_security.dmarc ? 'success' : 'danger'" size="small">
                      DMARC {{ d.data.mail_security.dmarc ? '✓' : '✗ 缺失' }}
                    </el-tag>
                  </div>
                </div>
              </div>
            </el-tab-pane>

            <!-- JS 分析（可折叠手风琴，避免数据多时乱） -->
            <el-tab-pane v-if="detail.js_findings?.length" :name="'js'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Coin /></el-icon>
                  JS 分析
                  <span class="tab-count">{{ detail.js_findings.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <el-collapse class="js-collapse">
                  <el-collapse-item v-for="(j, i) in detail.js_findings" :key="i" :name="i">
                    <!-- 折叠标题：文件名 + 统计标签 -->
                    <template #title>
                      <div class="js-collapse-title">
                        <span class="mono js-file-name">{{ j.js_url?.split('/').pop() || j.js_url }}</span>
                        <el-tag v-if="j.secrets?.length" type="danger" size="small">{{ j.secrets.length }} 密钥</el-tag>
                        <el-tag v-if="j.api_endpoints?.length" type="info" size="small">{{ j.api_endpoints.length }} API</el-tag>
                      </div>
                    </template>
                    <!-- 展开内容 -->
                    <div class="js-detail">
                      <!-- 文件 URL -->
                      <div class="js-detail-row">
                        <span class="js-detail-label">URL</span>
                        <a :href="j.js_url" target="_blank" rel="noopener" class="mono js-detail-url">{{ j.js_url }}</a>
                      </div>
                      <!-- 密钥泄露（表格，避免平铺乱） -->
                      <div v-if="j.secrets?.length" class="js-detail-section">
                        <div class="js-section-title danger">⚠ 密钥泄露 ({{ j.secrets.length }})</div>
                        <el-table :data="j.secrets" size="small" max-height="200" class="js-table">
                          <el-table-column prop="type" label="类型" width="140">
                            <template #default="{ row }">
                              <el-tag :type="row.severity === 'high' ? 'danger' : 'warning'" size="small">{{ row.type }}</el-tag>
                            </template>
                          </el-table-column>
                          <el-table-column prop="match" label="匹配内容" show-overflow-tooltip>
                            <template #default="{ row }"><span class="mono">{{ row.match }}</span></template>
                          </el-table-column>
                          <el-table-column prop="severity" label="级别" width="70" align="center" />
                        </el-table>
                      </div>
                      <!-- API 端点（表格 + 分页，避免 chip 平铺乱） -->
                      <div v-if="j.api_endpoints?.length" class="js-detail-section">
                        <div class="js-section-title">API 端点 ({{ j.api_endpoints.length }})</div>
                        <el-table :data="j.api_endpoints.map((url: string, idx: number) => ({ idx, url }))" size="small" max-height="300" class="js-table">
                          <el-table-column type="index" width="50" />
                          <el-table-column prop="url" label="端点路径" show-overflow-tooltip>
                            <template #default="{ row }"><span class="mono">{{ row.url }}</span></template>
                          </el-table-column>
                        </el-table>
                      </div>
                    </div>
                  </el-collapse-item>
                </el-collapse>
              </div>
            </el-tab-pane>

            <!-- 生命周期（该资产跨扫描的端口/技术栈变化趋势） -->
            <el-tab-pane v-if="detail.timeline?.length >= 2" :name="'timeline'">
              <template #label>
                <span class="tab-label">
                  <el-icon><Timer /></el-icon>
                  生命周期
                  <span class="tab-count">{{ detail.timeline.length }}</span>
                </span>
              </template>
              <div class="tab-content">
                <p class="timeline-hint">该资产在 {{ detail.timeline.length }} 次扫描中的端口与技术栈变化趋势</p>
                <v-chart class="timeline-chart" :option="timelineChartOption" autoresize />
                <!-- 明细表格 -->
                <el-table :data="detail.timeline" size="small" stripe class="timeline-table">
                  <el-table-column label="扫描时间" min-width="160">
                    <template #default="{ row }">
                      <span class="mono">{{ formatScanTime(row.started_at) }}</span>
                    </template>
                  </el-table-column>
                  <el-table-column prop="scan_name" label="任务" min-width="120" show-overflow-tooltip />
                  <el-table-column label="端口数" width="80" align="center">
                    <template #default="{ row }"><b class="mono">{{ row.port_count }}</b></template>
                  </el-table-column>
                  <el-table-column label="新增" width="70" align="center">
                    <template #default="{ row }">
                      <span v-if="row.ports_added" class="diff-add">+{{ row.ports_added }}</span>
                      <span v-else class="diff-zero">—</span>
                    </template>
                  </el-table-column>
                  <el-table-column label="消失" width="70" align="center">
                    <template #default="{ row }">
                      <span v-if="row.ports_removed" class="diff-remove">−{{ row.ports_removed }}</span>
                      <span v-else class="diff-zero">—</span>
                    </template>
                  </el-table-column>
                  <el-table-column label="技术栈" width="70" align="center">
                    <template #default="{ row }"><b class="mono">{{ row.tech_count }}</b></template>
                  </el-table-column>
                  <el-table-column label="新增" width="70" align="center">
                    <template #default="{ row }">
                      <span v-if="row.tech_added" class="diff-add">+{{ row.tech_added }}</span>
                      <span v-else class="diff-zero">—</span>
                    </template>
                  </el-table-column>
                  <el-table-column label="消失" width="70" align="center">
                    <template #default="{ row }">
                      <span v-if="row.tech_removed" class="diff-remove">−{{ row.tech_removed }}</span>
                      <span v-else class="diff-zero">—</span>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
            </el-tab-pane>
          </el-tabs>

          <!-- 全空兜底 -->
          <div
            v-if="!detail.ports?.length && !detail.web_info?.length
              && !detail.vulnerabilities?.length && !detail.tech_stack?.length
              && !detail.sensitive?.length && !detail.banners?.length"
            class="np-empty"
          >
            <el-icon :size="28" color="var(--np-text-disabled)"><Grid /></el-icon>
            <p>{{ t('common.noData') }}</p>
          </div>
        </template>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { getAssets, getAssetDetail } from '../api/scan'
import { usePageSize } from '../composables/usePageSetting'
import type { AssetSummary } from '../types'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart } from 'echarts/charts'
import { TooltipComponent, LegendComponent, GridComponent } from 'echarts/components'

use([CanvasRenderer, LineChart, TooltipComponent, LegendComponent, GridComponent])

const { t } = useI18n()

/** 归一化的技术栈项（兼容旧版 string 数组和新版 {name,version,confidence}） */
interface TechItem {
  name: string
  version?: string
  confidence?: number
  category?: string
}

/** 卡片预览数据：从详情接口抽取用于卡片展示的轻量字段 */
interface CardPreview {
  firstSite?: { url: string; status: number | null; title: string; tech: TechItem[]; server?: string }
  ports?: { port: number; proto: string }[]
  /** 头部主端口（站点端口优先，否则第一个开放端口） */
  primary?: { port: number; proto: string }
  vulnCount?: number
  lastScan?: string
}

/** 行数据：在 AssetSummary 上挂载预取态字段 */
interface AssetRow extends AssetSummary {
  rowKey: string
  _preview?: CardPreview
  _previewed?: boolean
}

const items = ref<AssetRow[]>([])
const loading = ref(false)
const query = ref('')
const sortBy = ref('hostname')
/** 分页 */
const page = ref(1)
const perPage = usePageSize('assets')
const pagedItems = computed(() => {
  const start = (page.value - 1) * perPage.value
  return items.value.slice(start, start + perPage.value)
})

/** 抽屉态 */
const drawerVisible = ref(false)
const detailTab = ref('vulns')
const detailLoading = ref(false)
const detail = ref<any>(null)
const detailError = ref<string>('')
const activeRow = ref<AssetRow | null>(null)
const drawerTitle = computed(() =>
  activeRow.value ? `${activeRow.value.ip}${activeRow.value.hostname && activeRow.value.hostname !== activeRow.value.ip ? ' · ' + activeRow.value.hostname : ''}` : t('assets.title')
)

async function loadData() {
  loading.value = true
  page.value = 1  // 重新搜索/排序后回到第一页
  try {
    const res = await getAssets(query.value, sortBy.value)
    items.value = (res.items || []).map(it => ({
      ...it,
      rowKey: `${it.hostname}::${it.ip}`,
      _previewed: false,
    }))
    // 后台并发预取详情（限流，避免瞬间打爆后端）
    prefetchPreviews(items.value)
  } finally {
    loading.value = false
  }
}

/** 限制并发的预取：让卡片逐步显示 web 站点/端口等富信息 */
async function prefetchPreviews(rows: AssetRow[]) {
  const CONCURRENCY = 6
  let cursor = 0
  const worker = async () => {
    while (cursor < rows.length) {
      const idx = cursor++
      const row = rows[idx]
      if (row._previewed) continue
      try {
        const d = await getAssetDetail(row.hostname, row.ip)
        row._preview = extractPreview(d)
      } catch {
        /* 预取失败静默，点击卡片时再正式加载 */
      } finally {
        row._previewed = true
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()))
}

/** 从详情响应抽取卡片展示所需的轻量结构 */
function extractPreview(d: any): CardPreview {
  if (!d) return {}
  const firstSite = (d.web_info?.length
    ? {
        url: d.web_info[0].url,
        status: d.web_info[0].status ?? null,
        title: d.web_info[0].title || '',
        tech: (d.web_info[0].tech || []).map((x: any) => _normalizeTech(x)).filter(Boolean),
        server: pickHeader(d.web_info[0].headers, 'Server'),
      }
    : undefined)
  const ports = (d.ports || []).slice(0, 12).map((p: any) => ({ port: p.port, proto: p.proto }))
  // 头部主端口：站点端口优先，否则第一个开放端口
  const sitePort = firstSite ? d.web_info[0].port : null
  const primaryPort = sitePort != null
    ? { port: sitePort, proto: 'https' /* 站点端口，proto 后面由 url 推断 */ }
    : (d.ports?.find?.((p: any) => p.state === 'open') || d.ports?.[0])
  const primary = primaryPort ? { port: primaryPort.port, proto: inferProto(firstSite?.url, primaryPort.proto) } : undefined
  const vulnCount = Array.isArray(d.vulnerabilities) ? d.vulnerabilities.length : 0
  const lastScan = d.last_scan || d.updated_at || ''
  return { firstSite, ports, primary, vulnCount, lastScan }
}

/** 从 headers 中按 key 取值（不区分大小写） */
function pickHeader(headers: any, key: string): string | undefined {
  if (!headers) return undefined
  const lower = String(key).toLowerCase()
  const hit = Object.entries(headers).find(([k]) => String(k).toLowerCase() === lower)
  return hit ? String(hit[1]) : undefined
}

/** 根据 url 协议或端口默认值推断协议 */
function inferProto(url?: string, fallback = 'tcp'): string {
  if (url?.startsWith('https://')) return 'https'
  if (url?.startsWith('http://')) return 'http'
  return fallback
}

/** 归一化技术栈项：兼容旧版 string 和新版 {name,version,confidence,category} */
function _normalizeTech(x: any): TechItem {
  if (typeof x === 'string') return { name: x }
  return {
    name: x?.name || '',
    version: x?.version || '',
    confidence: typeof x?.confidence === 'number' ? x.confidence : undefined,
    category: x?.category || '',
  }
}

/** 技术栈标签显示文本（带版本） */
function techLabel(tech: any): string {
  const t = typeof tech === 'string' ? { name: tech } : tech || {}
  return t.version ? `${t.name} ${t.version}` : (t.name || '')
}

/** 技术栈标签 hover tooltip（置信度 + 来源类型） */
function techTooltip(tech: any): string {
  const t = typeof tech === 'string' ? {} : tech || {}
  const parts: string[] = []
  if (t.category) parts.push(t.category)
  if (typeof t.confidence === 'number') parts.push(`置信度 ${t.confidence}%`)
  return parts.join(' · ') || ''
}

/** CDN/WAF 类标签用 warning 色，其余 info */
function techTagType(tech: any): '' | 'info' | 'warning' {
  const t = typeof tech === 'string' ? {} : tech || {}
  const cat = (t.category || '').toLowerCase()
  if (cat === 'cdn' || cat === 'waf') return 'warning'
  return 'info'
}

/** 格式化扫描时间（UTC → 本地可读） */
function formatScanTime(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

/** 拍平 WHOIS/RDAP 嵌套数据为 key→value 展示（取重要字段） */
function flattenWhois(data: any): Record<string, string> {
  if (!data || typeof data !== 'object') return {}
  const result: Record<string, string> = {}
  // 常见 RDAP/WHOIS 字段映射（中文名）
  const fieldMap: Record<string, string> = {
    'registrarName': '注册商', 'registrar': '注册商', 'sponsoring_registrar': '注册商',
    'registrationDate': '注册时间', 'created': '注册时间', 'registered': '注册时间',
    'creation_date': '注册时间',
    'expirationDate': '到期时间', 'expires': '到期时间', 'expiryDate': '到期时间',
    'expiration_date': '到期时间', 'expiration_time': '到期时间',
    'updated': '更新时间', 'updatedDate': '更新时间', 'updated_date': '更新时间',
    'status': '状态', 'statuses': '状态',
    'nameServers': 'NS 服务器', 'nameservers': 'NS 服务器',
    'asn': 'ASN', 'asnCidr': '网段', 'asn_cidr': '网段', 'cidr': '网段',
    'asn_description': 'ASN 描述', 'asn_country_code': '国家',
    'handle': 'HANDLE', 'entityType': '类型',
    'country': '国家', 'orgName': '组织', 'organization': '组织',
    'registrant': '注册人', 'email': '邮箱',
    'domain_name': '域名',
  }
  for (const [key, label] of Object.entries(fieldMap)) {
    let val = data[key]
    if (val === undefined) continue
    // 数组取前 3 个
    if (Array.isArray(val)) val = val.slice(0, 3).join(', ')
    if (typeof val === 'object') val = JSON.stringify(val)
    if (val && !result[label]) {
      result[label] = String(val).slice(0, 100)
    }
  }
  // 如果没匹配到标准字段，展示所有顶层字段（兜底）
  if (Object.keys(result).length === 0) {
    for (const [k, v] of Object.entries(data)) {
      if (v && typeof v !== 'object') result[k] = String(v).slice(0, 100)
      if (Object.keys(result).length >= 8) break
    }
  }
  return result
}

/** 生命周期趋势图配置：端口数/新增/消失 三条线 */
const timelineChartOption = computed(() => {
  const points = detail.value?.timeline || []
  if (points.length < 2) return {}
  const labels = points.map((p: any) => {
    const d = new Date(p.started_at)
    return `${d.getMonth() + 1}/${d.getDate()}`
  })
  return {
    tooltip: { trigger: 'axis' },
    legend: { bottom: 0, data: ['端口总数', '新增', '消失'] },
    grid: { left: 40, right: 20, top: 20, bottom: 40 },
    xAxis: { type: 'category', data: labels, boundaryGap: false },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      { name: '端口总数', type: 'line', smooth: true, data: points.map((p: any) => p.port_count), itemStyle: { color: '#60a5fa' }, areaStyle: { opacity: 0.1 } },
      { name: '新增', type: 'line', smooth: true, data: points.map((p: any) => p.ports_added), itemStyle: { color: '#22c55e' } },
      { name: '消失', type: 'line', smooth: true, data: points.map((p: any) => p.ports_removed), itemStyle: { color: '#ef4444' } },
    ],
  }
})

/** 点击卡片：打开抽屉并加载完整详情 */
async function openDetail(row: AssetRow) {
  activeRow.value = row
  drawerVisible.value = true
  detail.value = null
  detailError.value = ''
  detailLoading.value = true
  try {
    const d = await getAssetDetail(row.hostname, row.ip)
    detail.value = d || {}
    // 自动选第一个有数据的 Tab
    if (d.vulnerabilities?.length) detailTab.value = 'vulns'
    else if (d.ports?.length) detailTab.value = 'ports'
    else if (d.web_info?.length) detailTab.value = 'web'
    else if (d.sensitive?.length) detailTab.value = 'sensitive'
    else if (d.tech_stack?.length) detailTab.value = 'tech'
    else if (d.banners?.length) detailTab.value = 'banners'
    // 同步补齐预览
    if (!row._previewed) {
      row._preview = extractPreview(d)
      row._previewed = true
    }
  } catch (e: any) {
    detailError.value = e?.message || t('assets.detail.loadError')
  } finally {
    detailLoading.value = false
  }
}

function riskClass(score: number): string {
  if (score >= 70) return 'risk-high'
  if (score >= 40) return 'risk-medium'
  return 'risk-low'
}

/** HTTP 状态码 → el-tag 类型 */
function statusTagType(status: number) {
  if (status >= 200 && status < 300) return 'success'
  if (status >= 300 && status < 400) return 'warning'
  return 'danger'
}

/** 敏感路径等级 → el-tag 类型 */
function severityType(sev: string) {
  const s = (sev || '').toLowerCase()
  if (s === 'high' || s === 'critical') return 'danger'
  if (s === 'medium') return 'warning'
  return 'info'
}

/** 漏洞等级 → el-tag 类型 */
/** 漏洞按分类分组（nuclei 漏洞/安全头/CORS/弱口令/管理后台/真实IP） */
const vulnGroups = computed(() => {
  const vulns = detail.value?.vulnerabilities || []
  const groups: Record<string, { key: string; label: string; icon: string; items: any[] }> = {
    vuln:        { key: 'vuln', label: '已知漏洞', icon: '🔴', items: [] },
    security_header: { key: 'security_header', label: '安全响应头', icon: '🛡', items: [] },
    cors:        { key: 'cors', label: 'CORS 配置', icon: '🌐', items: [] },
    weak_password: { key: 'weak_password', label: '弱口令', icon: '🔑', items: [] },
    admin_panel: { key: 'admin_panel', label: '管理后台', icon: '⚙', items: [] },
    origin_ip:   { key: 'origin_ip', label: 'CDN真实IP', icon: '📍', items: [] },
    other:       { key: 'other', label: '其他', icon: '📋', items: [] },
  }
  for (const v of vulns) {
    const cat = v.category || ''
    if (cat in groups) groups[cat].items.push(v)
    else if (['cve', 'exposure', 'misconfig', 'default-login', 'takeover', 'vulnerability', 'detection'].includes(cat)) {
      groups.vuln.items.push(v)
    } else {
      groups.other.items.push(v)
    }
  }
  // 只返回有数据的组
  return Object.values(groups).filter(g => g.items.length > 0)
})

function vulnSeverityType(sev: string) {
  const s = (sev || '').toLowerCase()
  if (s === 'critical') return 'danger'
  if (s === 'high') return 'danger'
  if (s === 'medium') return 'warning'
  return 'info'
}

/* ═══ 协议分层（OSI / TCP-IP）═══ */
/** 服务/产品名 → OSI 层映射。命中即归类，未命中归 L7（绝大多数应用协议）。 */
const LAYER_BY_SERVICE: Record<string, number> = {
  // L6 表示层：加密 / 编码
  ssl: 6, tls: 6, 'ssl/http': 6, https: 6,
  // L5 会话层：会话管理
  rpc: 5, 'netbios-ssn': 5, llmnr: 5,
  // L4 传输层：端口级协议
  tcp: 4, udp: 4, tcpwrapped: 4,
  // L3 网络层
  ipv4: 3, ipv6: 3, icmp: 3, ip: 3,
}
/** 端口 → 典型服务（nmap 未识别 service 时的兜底，提高分层准确度） */
const SERVICE_BY_PORT: Record<number, string> = {
  80: 'http', 443: 'https', 8080: 'http', 8443: 'https', 8000: 'http', 8888: 'http',
  22: 'ssh', 21: 'ftp', 20: 'ftp', 23: 'telnet', 3389: 'rdp', 5900: 'vnc',
  25: 'smtp', 110: 'pop3', 143: 'imap', 465: 'smtps', 993: 'imaps', 995: 'pop3s',
  53: 'dns', 161: 'snmp', 162: 'snmptrap', 123: 'ntp', 69: 'tftp',
  3306: 'mysql', 5432: 'postgresql', 1433: 'mssql', 1521: 'oracle',
  6379: 'redis', 27017: 'mongodb', 9200: 'elasticsearch', 11211: 'memcached',
  389: 'ldap', 636: 'ldaps', 88: 'kerberos', 464: 'kpasswd', 135: 'msrpc',
}

/** 解析单个端口记录 → {layer, label}。label 取 service（兜底端口推断）。 */
function classifyPort(p: any): { layer: number; label: string } {
  const svc = (p.service || SERVICE_BY_PORT[p.port] || '').toLowerCase()
  const key = svc.includes('http') && svc.includes('ssl')
    ? 'https'
    : svc.replace(/[\d.]/g, '') // 'http-proxy' → 'http-proxy' 保留，'ssh-2.0' → 'ssh'
  const layer = LAYER_BY_SERVICE[key] ?? (svc ? 7 : 4) // 有 service 名默认 L7
  return { layer, label: svc || `:${p.port}/${p.proto}` }
}

/** OSI 七层定义（index 对应层号） */
const OSI_LAYERS = [
  { n: 7, name: '应用层', en: 'Application',  desc: '应用协议：HTTP/SSH/MySQL/Redis…', icon: '🌐' },
  { n: 6, name: '表示层', en: 'Presentation', desc: '数据格式化与加密：TLS/SSL',        icon: '🔐' },
  { n: 5, name: '会话层', en: 'Session',      desc: '会话建立与管理：RPC',              icon: '🤝' },
  { n: 4, name: '传输层', en: 'Transport',    desc: '端到端连接：TCP/UDP',              icon: '🚚' },
  { n: 3, name: '网络层', en: 'Network',      desc: '寻址与路由：IPv4/ICMP',            icon: '🗺️' },
  { n: 2, name: '数据链路层', en: 'Data Link', desc: '帧传输（本工具不扫描）',          icon: '🔗' },
  { n: 1, name: '物理层', en: 'Physical',     desc: '比特流传输（本工具不扫描）',       icon: '⚡' },
] as const
/** TCP/IP 五层：合并 OSI 5/6/7→应用，其余对齐 */
const TCPIP_LAYERS = [
  { n: 7, name: '应用层',   en: 'Application', desc: 'HTTP/SSH/MySQL/Redis + TLS 加密', icon: '🌐' },
  { n: 4, name: '传输层',   en: 'Transport',   desc: '端到端连接：TCP/UDP',            icon: '🚚' },
  { n: 3, name: '网络层',   en: 'Network',     desc: '寻址与路由：IPv4/ICMP',          icon: '🗺️' },
  { n: 2, name: '链路层',   en: 'Link',        desc: '帧传输（本工具不扫描）',         icon: '🔗' },
  { n: 1, name: '物理层',   en: 'Physical',    desc: '比特流传输（本工具不扫描）',     icon: '⚡' },
] as const

/** 分层模型切换：true=OSI七层, false=TCP/IP五层 */
const useOSI = ref(true)
const layerModel = computed(() => (useOSI.value ? OSI_LAYERS : TCPIP_LAYERS))

/** 把端口列表按层聚合，返回每层的服务清单与计数 */
const layerBreakdown = computed(() => {
  const ports = detail.value?.ports || []
  const byLayer: Record<number, { label: string; ports: any[]; count: number }[]> = {}
  for (const p of ports) {
    if (p.state && p.state !== 'open') continue          // 只统计 open 端口
    const { layer, label } = classifyPort(p)
    const bucket = byLayer[layer] ||= []
    let group = bucket.find(g => g.label === label)
    if (!group) {
      group = { label, ports: [], count: 0 }
      bucket.push(group)
    }
    group.ports.push(p)
    group.count++
  }
  return byLayer
})

/** 给定层号，返回该层的服务分组（兼容 OSI/TCP-IP：五层模型里 7 涵盖了原 5/6/7） */
function servicesAt(layerN: number) {
  if (useOSI.value) return layerBreakdown.value[layerN] || []
  // TCP/IP 五层：应用层归并 5/6/7
  if (layerN === 7) return [...(layerBreakdown.value[7] || []), ...(layerBreakdown.value[6] || []), ...(layerBreakdown.value[5] || [])]
  return layerBreakdown.value[layerN] || []
}

onMounted(loadData)
</script>

<style scoped>
.assets {
  
  
}

/* ═══ 资产表格 ═══ */
.asset-table {
  cursor: pointer;
}
.asset-table :deep(.el-table__row:hover > td) {
  background: var(--np-info-bg) !important;
}
/* 单元格通用 */
.cell-ip {
  font-weight: 700;
  color: var(--np-blue-500);
  white-space: nowrap;
}
.cell-host {
  color: var(--np-text-muted);
  font-size: 12px;
}
.cell-title {
  color: var(--np-text-primary);
}
.cell-server {
  color: var(--np-text-muted);
  font-size: 12px;
}
.cell-tech {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 3px;
  align-items: center;
}
.cell-tech .el-tag {
  font-family: var(--np-font-mono);
}
.tech-more {
  font-size: 11px;
  color: var(--np-text-muted);
  margin-left: 2px;
}
.cell-ports {
  color: var(--np-text-secondary);
  font-size: 12px;
}
.cell-vuln {
  color: var(--np-danger);
  font-weight: 700;
}
.cell-dash {
  color: var(--np-text-disabled);
}
.cell-risk {
  font-weight: 700;
  font-family: var(--np-font-mono);
}
.cell-risk.risk-high { color: var(--np-danger); }
.cell-risk.risk-medium { color: var(--np-warning); }
.cell-risk.risk-low { color: var(--np-success); }


/* ═══ 详情弹窗（居中大窗，固定高度，内容少也不缩） ═══ */
/* ═══ 详情弹窗（固定 88vh，内容再多也在内部滚动，绝不溢出） ═══ */
/* 注意：asset-dialog class 直接挂在 .el-dialog 根元素上（同一元素），
   不是后代关系。整条高度链必须贯通，任一环 min-height:0 缺失都会撑爆：
   el-dialog(88vh flex列) → __body(flex:1 撑满) → .dialog-body(h100%) →
   detail-overview(固定) → tabs(flex:1) → tab-content(滚动) */
:deep(.el-dialog.asset-dialog) {
  height: 88vh;
  margin-top: 6vh !important;
  margin-bottom: 0 !important;
  display: flex;
  flex-direction: column;
}
:deep(.el-dialog.asset-dialog .el-dialog__header) {
  flex-shrink: 0;
  margin-right: 0;
  padding-bottom: 14px;
}
:deep(.el-dialog.asset-dialog .el-dialog__body) {
  flex: 1;
  min-height: 0;            /* 关键：允许 flex 子项收缩，否则内容会撑爆 */
  padding: 0 20px 20px;
  overflow: hidden;
}
.dialog-body {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}
.drawer-error {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
  color: var(--np-danger);
  padding: var(--np-space-4) 0;
}

/* 顶部概览数字条 */
.detail-overview {
  display: flex;
  flex-wrap: wrap;
  gap: var(--np-space-5);
  padding-bottom: var(--np-space-3);
  margin-bottom: var(--np-space-4);
  border-bottom: 1px solid var(--np-border);
  flex-shrink: 0;
}
.detail-overview .ov-item {
  display: inline-flex;
  align-items: baseline;
  gap: var(--np-space-1);
  font-size: 13px;
  color: var(--np-text-muted);
}
.detail-overview .ov-item b {
  font-size: 18px;
  font-weight: 700;
  color: var(--np-text-primary);
}

/* 详情网格 */
.detail-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: var(--np-space-5);
}
.detail-section {
  min-width: 0;
}

/* 嵌套小表格 */
.mini-table {
  font-size: 12px;
}

/* Web 站点列表 */
.web-list {
  display: flex;
  flex-direction: column;
  gap: var(--np-space-3);
}
.web-card {
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
  padding: var(--np-space-3);
  background: var(--np-bg-app);
}
.web-head {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
  flex-wrap: wrap;
}
.web-url {
  font-size: 13px;
  font-weight: 500;
  color: var(--np-blue-500);
  word-break: break-all;
}
.web-url:hover {
  color: var(--np-blue-600);
}
.web-title {
  margin-top: var(--np-space-1);
  font-size: 13px;
  color: var(--np-text-secondary);
}
.web-meta {
  display: flex;
  gap: var(--np-space-3);
  margin-top: var(--np-space-2);
  color: var(--np-text-muted);
  font-size: 12px;
}
.web-meta .meta-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.web-tags {
  display: flex;
  flex-wrap: wrap;
  gap: var(--np-space-1);
  margin-top: var(--np-space-2);
}

/* 漏洞列表 */
.vuln-list {
  display: flex;
  flex-direction: column;
  gap: var(--np-space-2);
}
.vuln-group { margin-bottom: var(--np-space-4); }
.vuln-group-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  font-weight: 600;
  color: var(--np-text-secondary);
  margin-bottom: var(--np-space-2);
  padding-bottom: 4px;
  border-bottom: 1px solid var(--np-border);
}
.vuln-row {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
  flex-wrap: wrap;
  padding: var(--np-space-2);
  border-radius: var(--np-radius-sm);
  background: var(--np-danger-bg);
}
.vuln-name {
  font-size: 13px;
  color: var(--np-text-primary);
  flex: 1;
  min-width: 120px;
}
.vuln-cve {
  font-size: 12px;
  color: var(--np-blue-500);
}
.vuln-cve:hover {
  color: var(--np-blue-600);
  text-decoration: underline;
}
.cvss {
  font-size: 12px;
  color: var(--np-text-muted);
}

/* Banner 列表 */
.banner-list {
  display: flex;
  flex-direction: column;
  gap: var(--np-space-2);
}
.banner-row {
  display: grid;
  grid-template-columns: 70px 90px 1fr;
  gap: var(--np-space-2);
  align-items: start;
  padding: var(--np-space-2);
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-sm);
  background: var(--np-bg-app);
}
.banner-port {
  color: var(--np-text-secondary);
  font-weight: 600;
}
.banner-service {
  color: var(--np-text-secondary);
  font-size: 13px;
}
.banner-text {
  margin: 0;
  font-size: 12px;
  color: var(--np-text-muted);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 120px;
  overflow-y: auto;
}

/* 响应式 */
@media (max-width: 768px) {
  .banner-row {
    grid-template-columns: 1fr;
  }
}

/* ═══ 协议分层 ═══ */
.layer-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--np-space-3);
  flex-wrap: wrap;
  margin-bottom: var(--np-space-4);
}
.layer-hint {
  font-size: 12px;
  color: var(--np-text-muted);
}

/* 分层栈：每层一行，从上(7)到下(1) */
.layer-stack {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-lg);
  overflow: hidden;
}
.layer-row {
  display: grid;
  grid-template-columns: 168px 1fr;
  align-items: stretch;
  border-bottom: 1px solid var(--np-border);
  transition: background 150ms ease;
}
.layer-row:last-child {
  border-bottom: none;
}
/* 有暴露的层：高亮左边框 + 浅底色 */
.layer-row.layer-active {
  background: var(--np-info-bg);
}
.layer-row.layer-active .layer-label {
  border-left: 3px solid var(--np-blue-500);
}
.layer-row:not(.layer-active) {
  opacity: 0.6;
}

/* 左：层标识（垂直居中） */
.layer-label {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
  padding: 12px 14px;
  background: var(--np-bg-elevated);
  border-left: 3px solid transparent;
}
.layer-num {
  flex-shrink: 0;
  width: 30px;
  height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: var(--np-blue-500);
  color: #fff;
  font-size: 12px;
  font-weight: 700;
  font-family: var(--np-font-mono);
}
.layer-row:not(.layer-active) .layer-num {
  background: var(--np-bg-overlay);
  color: var(--np-text-disabled);
}
.layer-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--np-text-primary);
}
.layer-en {
  font-size: 11px;
  color: var(--np-text-muted);
}

/* 右：服务标签 */
.layer-services {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  padding: 12px 14px;
  min-height: 56px;
}
.svc-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 10px;
  background: var(--np-bg-layout);
  border: 1px solid var(--np-border);
  border-radius: 12px;
  font-size: 12px;
  color: var(--np-text-secondary);
  cursor: pointer;
  transition: all 150ms ease;
}
.svc-chip:hover {
  background: var(--np-blue-500);
  border-color: var(--np-blue-500);
  color: #fff;
}
.svc-chip b {
  font-size: 11px;
  color: var(--np-blue-500);
}
.svc-chip:hover b {
  color: #fff;
}
.layer-empty {
  color: var(--np-text-disabled);
  font-size: 13px;
}

/* 服务弹出详情 */
.svc-pop {
  max-height: 320px;
  overflow-y: auto;
}
.svc-pop-title {
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 8px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--np-border);
}
.svc-pop-port {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  padding: 4px 0;
  font-size: 12px;
}
.svc-pop-port .mono {
  color: var(--np-blue-500);
  font-weight: 600;
}
.svc-pop-prod {
  color: var(--np-text-muted);
  text-align: right;
}

/* 底部攻击面小结 */
.layer-summary {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--np-space-3);
  margin-top: var(--np-space-4);
  padding: var(--np-space-3) var(--np-space-4);
  background: var(--np-bg-elevated);
  border-radius: var(--np-radius-lg);
  font-size: 13px;
}
.layer-summary .ls-label {
  color: var(--np-text-muted);
}
.layer-summary .ls-item {
  color: var(--np-text-secondary);
}
.layer-summary .ls-item b {
  color: var(--np-blue-500);
  font-family: var(--np-font-mono);
  margin-left: 2px;
}
.layer-summary .ls-item.zero {
  opacity: 0.4;
}
.layer-summary .ls-item.zero b {
  color: var(--np-text-disabled);
}

/* ── 生命周期 Tab ── */
/* ── WHOIS Tab ── */
.whois-block { margin-bottom: var(--np-space-4); }
.whois-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.whois-target { font-weight: 600; color: var(--np-text-primary); }
.whois-time { font-size: 12px; color: var(--np-text-muted); margin-left: auto; }
.whois-desc { width: 100%; }

/* ── DNS 记录 Tab ── */
.dns-block { margin-bottom: var(--np-space-4); }
.dns-head { margin-bottom: 8px; }
.dns-target { font-weight: 600; color: var(--np-text-primary); }
.dns-warnings { margin-bottom: 8px; }
.dns-warn { font-size: 12px; color: var(--np-warning); padding: 2px 0; }
.dns-desc { width: 100%; }
.dns-val { font-size: 12px; color: var(--np-text-secondary); word-break: break-all; }
.dns-mailsec { display: flex; gap: 8px; margin-top: 8px; }

/* ── JS 分析 Tab（可折叠式）── */
.js-collapse { border-top: none; }
.js-collapse :deep(.el-collapse-item__header) {
  height: 44px;
  padding: 0 12px;
  border-radius: var(--np-radius-md);
  border: 1px solid var(--np-border);
  margin-bottom: 6px;
  background: var(--np-bg-elevated);
}
.js-collapse :deep(.el-collapse-item__wrap) {
  border: none;
}
.js-collapse :deep(.el-collapse-item__content) {
  padding: 12px 0 0;
}
.js-collapse-title {
  display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0;
}
.js-file-name {
  font-size: 13px; font-weight: 500; color: var(--np-text-primary);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  flex: 1; min-width: 0;
}
.js-detail { padding: 0 4px; }
.js-detail-row {
  display: flex; align-items: baseline; gap: 8px; margin-bottom: 8px;
}
.js-detail-label { font-size: 12px; color: var(--np-text-muted); flex-shrink: 0; }
.js-detail-url {
  font-size: 12px; color: var(--np-blue-500);
  word-break: break-all;
}
.js-detail-section { margin-bottom: var(--np-space-3); }
.js-section-title {
  font-size: 13px; font-weight: 600; color: var(--np-text-secondary);
  margin-bottom: 6px;
}
.js-section-title.danger { color: var(--np-danger); }
.js-table { width: 100%; }

.timeline-hint {
  font-size: 12px;
  color: var(--np-text-muted);
  margin-bottom: var(--np-space-3);
}
.timeline-chart {
  height: 260px;
  margin-bottom: var(--np-space-4);
}
.timeline-table {
  margin-top: var(--np-space-2);
}
.diff-add { color: #22c55e; font-weight: 600; }
.diff-remove { color: #ef4444; font-weight: 600; }
.diff-zero { color: var(--np-text-disabled); }

/* ── Tab 样式 ── */
.detail-tabs {
  margin-top: var(--np-space-4);
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-height: 0;
}

.detail-tabs :deep(.el-tabs__header) {
  margin-bottom: var(--np-space-3);
  flex-shrink: 0;
}

.detail-tabs :deep(.el-tabs__content) {
  flex: 1;
  overflow: hidden;
  min-height: 0;
}

.detail-tabs :deep(.el-tab-pane) {
  height: 100%;
  min-height: 0;            /* flex 子项允许收缩，内容超高不撑爆父级 */
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.detail-tabs :deep(.el-tabs__nav-wrap::after) {
  background-color: var(--np-border);
}

.tab-label {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
}

.tab-count {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  border-radius: 9px;
  background: var(--np-bg-elevated);
  color: var(--np-text-muted);
  font-size: 10px;
  font-weight: 700;
  font-family: var(--np-font-mono);
}

.tab-count.danger {
  background: var(--np-danger-bg);
  color: var(--np-danger);
}

.tab-count.warn {
  background: var(--np-warning-bg);
  color: var(--np-warning);
}

.tab-content {
  flex: 1;
  min-height: 0;            /* 真正的滚动容器：填满 tab-pane 剩余空间并在内部滚动 */
  overflow-y: auto;
  padding-right: 4px;
}

.tech-tags-detail {
  gap: var(--np-space-2);
}

.tech-tags-detail .el-tag {
  font-size: 13px;
  padding: 4px 12px;
}

/* 技术栈表格 */
.tech-table .tech-name { font-weight: 600; color: var(--np-text-primary); }
.tech-table .tech-version { color: var(--np-blue-500); font-weight: 500; }
.tech-table .tech-confidence { color: var(--np-text-muted); }
.tech-conf-high { color: var(--np-success); font-weight: 600; }
.tech-conf-low { color: var(--np-text-muted); }
</style>
