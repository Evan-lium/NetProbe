#!/usr/bin/env python3
"""离线扩充指纹库 — 补充高频技术栈规则（含版本提取）。"""
import json
from pathlib import Path

FP_PATH = Path(__file__).parent.parent / "netprobe" / "data" / "fingerprints.json"

fps = json.load(open(FP_PATH, encoding="utf-8"))
existing = {fp["name"].lower() for fp in fps}

NEW_RULES = [
    # Web 服务器/中间件
    {"name":"Tengine","category":"Server","patterns":[{"type":"header","pattern":"Server: Tengine","version":"re:Tengine/([0-9.]+)"}]},
    {"name":"Caddy","category":"Server","patterns":[{"type":"header","pattern":"Server: Caddy","version":"re:Caddy/([0-9.]+)"}]},
    {"name":"Lighttpd","category":"Server","patterns":[{"type":"header","pattern":"Server: lighttpd","version":"re:lighttpd/([0-9.]+)"}]},
    {"name":"Jetty","category":"Server","patterns":[{"type":"header","pattern":"Server: Jetty","version":"re:Jetty\\(([0-9.]+)"}]},
    {"name":"LiteSpeed","category":"Server","patterns":[{"type":"header","pattern":"Server: LiteSpeed"}]},
    {"name":"Traefik","category":"Server","patterns":[{"type":"header","pattern":"Server: Traefik"}]},
    {"name":"Envoy","category":"Server","patterns":[{"type":"header","pattern":"Server: envoy"}]},
    {"name":"HAProxy","category":"Server","patterns":[{"type":"header","pattern":"Server: HAProxy"}]},
    {"name":"Varnish","category":"CDN","patterns":[{"type":"header","pattern":"X-Varnish"},{"type":"header","pattern":"Server: Varnish"}]},
    {"name":"Squid","category":"CDN","patterns":[{"type":"header","pattern":"Server: squid"}]},
    # 国产面板
    {"name":"宝塔面板","category":"Web服务器面板","patterns":[{"type":"header","pattern":"BT-PANEL"},{"type":"header","pattern":"Bt-Panel"}]},
    {"name":"phpMyAdmin","category":"Database面板","patterns":[{"type":"html","pattern":"phpmyadmin"},{"type":"header","pattern":"Set-Cookie: phpMyAdmin"},{"type":"html","pattern":"re:meta name=.generator. content=.phpMyAdmin","version":"re:phpMyAdmin\\s+([0-9.]+)"}]},
    {"name":"Adminer","category":"Database面板","patterns":[{"type":"html","pattern":"adminer.org"}]},
    # 框架
    {"name":"Django","category":"Framework","patterns":[{"type":"cookie","pattern":"csrftoken"},{"type":"cookie","pattern":"sessionid"}]},
    {"name":"Rails","category":"Framework","patterns":[{"type":"header","pattern":"X-Powered-By: Phusion Passenger"},{"type":"cookie","pattern":"_rails"}]},
    {"name":"Next.js","category":"Framework","patterns":[{"type":"header","pattern":"X-Powered-By: Next.js","version":"re:Next\\.js\\s*([0-9.]+)"},{"type":"html","pattern":"__NEXT_DATA__"}]},
    {"name":"Nuxt.js","category":"Framework","patterns":[{"type":"html","pattern":"__NUXT__"}]},
    {"name":"Gatsby","category":"Framework","patterns":[{"type":"html","pattern":"gatsby-"}]},
    {"name":"NestJS","category":"Framework","patterns":[{"type":"header","pattern":"X-Powered-By: NestJS"}]},
    {"name":"Fastify","category":"Framework","patterns":[{"type":"header","pattern":"X-Powered-By: Fastify"}]},
    {"name":"CodeIgniter","category":"Framework","patterns":[{"type":"header","pattern":"X-Powered-By: CodeIgniter"}]},
    {"name":"Yii","category":"Framework","patterns":[{"type":"cookie","pattern":"YII"}]},
    {"name":"FastAPI","category":"Framework","patterns":[{"type":"header","pattern":"X-Powered-By: FastAPI"}]},
    {"name":"Beego","category":"Framework","patterns":[{"type":"header","pattern":"X-Powered-By: Beego"}]},
    {"name":"Echo","category":"Framework","patterns":[{"type":"header","pattern":"X-Powered-By: Echo"}]},
    {"name":"Actix","category":"Framework","patterns":[{"type":"header","pattern":"Server: Actix"}]},
    # JS 框架/库
    {"name":"React","category":"JS库","patterns":[{"type":"html","pattern":"_reactRootContainer"},{"type":"script_src","pattern":"react"}]},
    {"name":"Angular","category":"JS库","patterns":[{"type":"html","pattern":"ng-version"},{"type":"html","pattern":"ng-app"}]},
    {"name":"Svelte","category":"JS库","patterns":[{"type":"html","pattern":"__svelte"}]},
    {"name":"Ember.js","category":"JS库","patterns":[{"type":"script_src","pattern":"ember"}]},
    {"name":"jQuery","category":"JS库","patterns":[{"type":"script_src","pattern":"jquery","version":"re:jquery[.-]([0-9.]+)"}]},
    {"name":"Bootstrap","category":"CSS框架","patterns":[{"type":"script_src","pattern":"bootstrap"}]},
    {"name":"Tailwind CSS","category":"CSS框架","patterns":[{"type":"html","pattern":"tailwind"}]},
    {"name":"Ant Design","category":"CSS框架","patterns":[{"type":"script_src","pattern":"ant-design"},{"type":"script_src","pattern":"antd"}]},
    {"name":"Material-UI","category":"CSS框架","patterns":[{"type":"script_src","pattern":"material-ui"}]},
    {"name":"Vuetify","category":"CSS框架","patterns":[{"type":"script_src","pattern":"vuetify"}]},
    # CMS
    {"name":"Hexo","category":"CMS","patterns":[{"type":"meta","pattern":"Hexo","version":"re:Hexo\\s+([0-9.]+)"}]},
    {"name":"Typecho","category":"CMS","patterns":[{"type":"meta","pattern":"Typecho"},{"type":"header","pattern":"X-Powered-By: Typecho"}]},
    {"name":"Z-Blog","category":"CMS","patterns":[{"type":"meta","pattern":"Z-Blog"}]},
    {"name":"PHPCMS","category":"CMS","patterns":[{"type":"meta","pattern":"PHPCMS"}]},
    # 国产 OA
    {"name":"通达OA","category":"OA","patterns":[{"type":"html","pattern":"MYOA"},{"type":"html","pattern":"tongda"}]},
    {"name":"泛微OA","category":"OA","patterns":[{"type":"cookie","pattern":"ecology"},{"type":"html","pattern":"weaver"}]},
    {"name":"蓝凌OA","category":"OA","patterns":[{"type":"html","pattern":"landray"}]},
    {"name":"用友NC","category":"OA","patterns":[{"type":"html","pattern":"yonyou"}]},
    # 数据库面板
    {"name":"Redis Commander","category":"Database面板","patterns":[{"type":"html","pattern":"redis-commander"}]},
    {"name":"Mongo Express","category":"Database面板","patterns":[{"type":"header","pattern":"mongo-express"}]},
    {"name":"pgAdmin","category":"Database面板","patterns":[{"type":"cookie","pattern":"pgAdmin"}]},
    # 监控/运维
    {"name":"Grafana","category":"监控","patterns":[{"type":"header","pattern":"X-Grafana"}]},
    {"name":"Prometheus","category":"监控","patterns":[{"type":"header","pattern":"Server: Prometheus"}]},
    {"name":"Kibana","category":"监控","patterns":[{"type":"header","pattern":"kbn-version"}]},
    {"name":"Elasticsearch","category":"监控","patterns":[{"type":"header","pattern":"Server: Elasticsearch"}]},
    {"name":"Jenkins","category":"监控","patterns":[{"type":"header","pattern":"X-Jenkins","version":"re:X-Jenkins:\\s*([0-9.]+)"}]},
    {"name":"GitLab","category":"监控","patterns":[{"type":"header","pattern":"X-Gitlab"}]},
    {"name":"Nacos","category":"监控","patterns":[{"type":"header","pattern":"Nacos"}]},
    {"name":"Druid Monitor","category":"监控","patterns":[{"type":"html","pattern":"datasource.html"}]},
    {"name":"Spring Boot Actuator","category":"监控","patterns":[{"type":"header","pattern":"X-Application-Context"}]},
    {"name":"SonarQube","category":"监控","patterns":[{"type":"html","pattern":"sonarqube"}]},
    # CDN 补充
    {"name":"Azure CDN","category":"CDN","patterns":[{"type":"header","pattern":"X-Azure-CDN"}]},
    {"name":"Bunny CDN","category":"CDN","patterns":[{"type":"header","pattern":"Server: BunnyCDN"}]},
    {"name":"KeyCDN","category":"CDN","patterns":[{"type":"header","pattern":"X-CDN: KeyCDN"}]},
    {"name":"七牛云CDN","category":"CDN","patterns":[{"type":"header","pattern":"X-Qiniu"}]},
    {"name":"又拍云CDN","category":"CDN","patterns":[{"type":"header","pattern":"X-Cache: Upyun"}]},
    # WAF 补充
    {"name":"ModSecurity","category":"WAF","patterns":[{"type":"header","pattern":"Mod_Security"}]},
    {"name":"F5 BIG-IP","category":"WAF","patterns":[{"type":"cookie","pattern":"BIGipServer"}]},
    {"name":"绿盟WAF","category":"WAF","patterns":[{"type":"header","pattern":"Server: NSFOCUS"}]},
    {"name":"安恒WAF","category":"WAF","patterns":[{"type":"header","pattern":"Server: Anheng"}]},
    # Runtime 版本提取
    {"name":"Node.js","category":"Runtime","patterns":[{"type":"header","pattern":"X-Powered-By: Node.js"}]},
    {"name":"Ruby","category":"Runtime","patterns":[{"type":"header","pattern":"Server: Ruby"}]},
    {"name":"ASP.NET","category":"Runtime","patterns":[{"type":"header","pattern":"X-AspNet-Version","version":"re:X-AspNet-Version:\\s*([0-9.]+)"},{"type":"cookie","pattern":"ASP.NET_SessionId"}]},
]

added = 0
for rule in NEW_RULES:
    if rule["name"].lower() not in existing:
        fps.append(rule)
        existing.add(rule["name"].lower())
        added += 1

with_version = sum(1 for fp in fps for p in fp["patterns"] if "version" in p)
json.dump(fps, open(FP_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(f"新增 {added} 条，总计 {len(fps)} 条，带 version {with_version} 条")
