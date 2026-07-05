#!/usr/bin/env python3
"""第三轮指纹扩充 — 参考 FOFA/Wappalyzer/Shodan/EHole 的检测逻辑，
补充国内产品、物联网设备、安全设备、云平台等高频指纹。"""
import json
from pathlib import Path

FP_PATH = Path(__file__).parent.parent / "netprobe" / "data" / "fingerprints.json"
fps = json.load(open(FP_PATH, encoding="utf-8"))
existing = {fp["name"].lower() for fp in fps}

# 参考 FOFA/EHole/Shodan 的指纹特征，补充我们缺失的高价值规则
NEW_RULES = [
    # ═══ 国产 Web 应用 / CMS ═══
    {"name":"蝉知CMS","category":"CMS","patterns":[
        {"type":"meta","pattern":"chanzhi"}]},
    {"name":"PHPSHE","category":"Ecommerce","patterns":[
        {"type":"meta","pattern":"phpshe"}]},
    {"name":"ECShop","category":"Ecommerce","patterns":[
        {"type":"html","pattern":"ecs_hash"},
        {"type":"html","pattern":"ecshop"}]},
    {"name":"ShopEX","category":"Ecommerce","patterns":[
        {"type":"html","pattern":"shopex"},
        {"type":"cookie","pattern":"S[shopEX]"}]},
    {"name":"V5SHOP","category":"Ecommerce","patterns":[
        {"type":"html","pattern":"v5shop"}]},
    {"name":"建站之星","category":"CMS","patterns":[
        {"type":"html","pattern":"sitestar"}]},
    {"name":"PageAdmin","category":"CMS","patterns":[
        {"type":"cookie","pattern":"PageAdmin"}]},
    {"name":"EasyTalk","category":"Forum","patterns":[
        {"type":"meta","pattern":"EasyTalk"}]},
    {"name":"DiscuzX","category":"Forum","patterns":[
        {"type":"meta","pattern":"Discuz"},
        {"type":"html","pattern":"discuz_uid"}]},
    {"name":"phpBB","category":"Forum","patterns":[
        {"type":"html","pattern":"phpBB"},
        {"type":"html","pattern":"phpbb"}]},
    {"name":"myBB","category":"Forum","patterns":[
        {"type":"cookie","pattern":"mybb"}]},
    {"name":"Flarum","category":"Forum","patterns":[
        {"type":"html","pattern":"flarum"}]},

    # ═══ 路由器 / 网络设备 ═══
    {"name":"TP-Link路由器","category":"Server","patterns":[
        {"type":"header","pattern":"Server: TP-LINK"},
        {"type":"html","pattern":"TP-LINK"}]},
    {"name":"华为路由器","category":"Server","patterns":[
        {"type":"header","pattern":"Server: H3C"},
        {"type":"html","pattern":"Huawei"}]},
    {"name":"小米路由器","category":"Server","patterns":[
        {"type":"html","pattern":"MiWiFi"}]},
    {"name":"华硕路由器","category":"Server","patterns":[
        {"type":"html","pattern":"asus"},
        {"type":"html","pattern":"rt-"}]},
    {"name":"OpenWrt","category":"Server","patterns":[
        {"type":"header","pattern":"Server: OpenWRT"},
        {"type":"html","pattern":"openwrt"}]},
    {"name":"DD-WRT","category":"Server","patterns":[
        {"type":"html","pattern":"dd-wrt"}]},
    {"name":"MikroTik","category":"Server","patterns":[
        {"type":"header","pattern":"Server: Mikrotik"}]},
    {"name":"Untangle","category":"Server","patterns":[
        {"type":"header","pattern":"Server: Untangle"}]},

    # ═══ 安全设备 / WAF ═══
    {"name":"深信服VPN","category":"WAF","patterns":[
        {"type":"html","pattern":" Sangfor"},
        {"type":"html","pattern":"SSL VPN"}]},
    {"name":"深信服AC","category":"WAF","patterns":[
        {"type":"html","pattern":"SANGFOR"},
        {"type":"cookie","pattern":"sangfor"}]},
    {"name":"天融信防火墙","category":"WAF","patterns":[
        {"type":"header","pattern":"Server: Topsec"}]},
    {"name":"华为防火墙","category":"WAF","patterns":[
        {"type":"html","pattern":"USG"},
        {"type":"header","pattern":"Server: Huawei"}]},
    {"name":"山石防火墙","category":"WAF","patterns":[
        {"type":"html","pattern":"Hillstone"}]},
    {"name":"启明星辰","category":"WAF","patterns":[
        {"type":"html","pattern":"Venustech"}]},
    {"name":"网御星云","category":"WAF","patterns":[
        {"type":"html","pattern":"LeadSec"}]},
    {"name":"长亭WAF","category":"WAF","patterns":[
        {"type":"header","pattern":"Server: Chaitin"},
        {"type":"header","pattern":"X-Ray"}]},
    {"name":"安全狗","category":"WAF","patterns":[
        {"type":"header","pattern":"Server: Safe3"},
        {"type":"header","pattern":"x-powered-by: Safedog"}]},
    {"name":"360网站卫士","category":"WAF","patterns":[
        {"type":"header","pattern":"X-Powered-By-360WZB"}]},
    {"name":"Cloudflare WAF","category":"WAF","patterns":[
        {"type":"header","pattern":"cf-ray"},
        {"type":"header","pattern":"Server: cloudflare"}]},
    {"name":"Imperva","category":"WAF","patterns":[
        {"type":"header","pattern":"X-Iinfo"},
        {"type":"cookie","pattern":"incap_ses"}]},
    {"name":"Wordfence","category":"WAF","patterns":[
        {"type":"header","pattern":"X-WPE"}]},

    # ═══ 摄像头 / IoT ═══
    {"name":"海康威视","category":"监控","patterns":[
        {"type":"html","pattern":"hikvision"},
        {"type":"html","pattern":"Hikvision"},
        {"type":"html","pattern":"webComponents"}]},
    {"name":"大华摄像头","category":"监控","patterns":[
        {"type":"html","pattern":"dahua"},
        {"type":"html","pattern":"DVR"}]},
    {"name":"宇视摄像头","category":"监控","patterns":[
        {"type":"html","pattern":"uniview"}]},
    {"name":"雄迈摄像头","category":"监控","patterns":[
        {"type":"html","pattern":"XiongMai"},
        {"type":"html","pattern":"goke"}]},
    {"name":"天地伟业","category":"监控","patterns":[
        {"type":"html","pattern":"Tiandy"}]},
    {"name":"RSTP服务","category":"监控","patterns":[
        {"type":"header","pattern":"Server: Golang"}]},

    # ═══ 云平台 / 容器 ═══
    {"name":"阿里云OSS","category":"CDN","patterns":[
        {"type":"header","pattern":"Server: AliyunOSS"},
        {"type":"header","pattern":"x-oss"}]},
    {"name":"腾讯云COS","category":"CDN","patterns":[
        {"type":"header","pattern":"Server: tencent-cos"},
        {"type":"header","pattern":"x-cos"}]},
    {"name":"AWS S3","category":"CDN","patterns":[
        {"type":"header","pattern":"Server: AmazonS3"},
        {"type":"header","pattern":"x-amz"}]},
    {"name":"MinIO","category":"Server","patterns":[
        {"type":"header","pattern":"Server: MinIO"}]},
    {"name":"Rancher","category":"监控","patterns":[
        {"type":"header","pattern":"X-Rancher"}]},
    {"name":"Portainer","category":"监控","patterns":[
        {"type":"html","pattern":"portainer"}]},
    {"name":"Kubernetes Dashboard","category":"监控","patterns":[
        {"type":"html","pattern":"kubernetes-dashboard"},
        {"type":"header","pattern":"Server: dashboard"}]},
    {"name":"Docker Registry","category":"监控","patterns":[
        {"type":"header","pattern":"Docker-Distribution"}]},
    {"name":"cPanel","category":"Web服务器面板","patterns":[
        {"type":"header","pattern":"Server: cPanel"},
        {"type":"html","pattern":"cpanel"}]},
    {"name":"Plesk","category":"Web服务器面板","patterns":[
        {"type":"header","pattern":"X-Powered-By: Plesk"},
        {"type":"html","pattern":"plesk"}]},
    {"name":"Webmin","category":"Web服务器面板","patterns":[
        {"type":"header","pattern":"Server: MiniServ"}]},
    {"name":"DirectAdmin","category":"Web服务器面板","patterns":[
        {"type":"header","pattern":"Server: DirectAdmin"}]},
    {"name":"ISPmanager","category":"Web服务器面板","patterns":[
        {"type":"header","pattern":"Server: ISPmanager"}]},

    # ═══ 开发工具 / CI/CD ═══
    {"name":"Gitea","category":"监控","patterns":[
        {"type":"header","pattern":"X-Frame-Options: SAMEORIGIN"},
        {"type":"html","pattern":"gitea"}]},
    {"name":"Gogs","category":"监控","patterns":[
        {"type":"html","pattern":"gogs"}]},
    {"name":"Bitbucket","category":"监控","patterns":[
        {"type":"header","pattern":"X-ARENDERID"}]},
    {"name":"Drone CI","category":"监控","patterns":[
        {"type":"header","pattern":"Server: Drone"}]},
    {"name":"CircleCI","category":"监控","patterns":[
        {"type":"header","pattern":"Server: CircleCI"}]},
    {"name":"TeamCity","category":"监控","patterns":[
        {"type":"header","pattern":"Server: TeamCity"}]},
    {"name":"Bamboo","category":"监控","patterns":[
        {"type":"cookie","pattern":"bamboo"}]},
    {"name":"Confluence","category":"OA","patterns":[
        {"type":"header","pattern":"X-Confluence"},
        {"type":"html","pattern":"confluence"}]},
    {"name":"Jira","category":"OA","patterns":[
        {"type":"header","pattern":"X-ARENDERID"},
        {"type":"html","pattern":"jira"},
        {"type":"cookie","pattern":"atlassian"}]},
    {"name":"Redmine","category":"OA","patterns":[
        {"type":"html","pattern":"redmine"}]},

    # ═══ 统计 / 分析 ═══
    {"name":"百度统计","category":"Analytics","patterns":[
        {"type":"script_src","pattern":"hm.baidu.com"},
        {"type":"html","pattern":"hm.baidu.com"}]},
    {"name":"Google Analytics","category":"Analytics","patterns":[
        {"type":"script_src","pattern":"google-analytics.com"},
        {"type":"html","pattern":"google-analytics.com"}]},
    {"name":"友盟统计","category":"Analytics","patterns":[
        {"type":"script_src","pattern":"umeng"},
        {"type":"html","pattern":"umeng"}]},
    {"name":"Piwik","category":"Analytics","patterns":[
        {"type":"script_src","pattern":"piwik"},
        {"type":"html","pattern":"piwik"}]},
    {"name":"Mixpanel","category":"Analytics","patterns":[
        {"type":"script_src","pattern":"mixpanel"}]},
    {"name":"Hotjar","category":"Analytics","patterns":[
        {"type":"script_src","pattern":"hotjar"}]},
    {"name":"CNZZ统计","category":"Analytics","patterns":[
        {"type":"script_src","pattern":"cnzz"},
        {"type":"html","pattern":"cnzz"}]},
    {"name":"51LA统计","category":"Analytics","patterns":[
        {"type":"script_src","pattern":"51.la"},
        {"type":"html","pattern":"51.la"}]},

    # ═══ Web 框架（补充）═══
    {"name":"Meteor","category":"Framework","patterns":[
        {"type":"html","pattern":"__meteor_runtime_config__"}]},
    {"name":"Aurelia","category":"Framework","patterns":[
        {"type":"html","pattern":"aurelia"}]},
    {"name":"Stimulus","category":"Framework","patterns":[
        {"type":"script_src","pattern":"stimulus"}]},
    {"name":"Phoenix","category":"Framework","patterns":[
        {"type":"html","pattern":"phoenix"},
        {"type":"html","pattern":"data-phx-"}]},
    {"name":"Laravel","category":"Framework","patterns":[
        {"type":"cookie","pattern":"laravel_session"}]},
    {"name":"Symfony","category":"Framework","patterns":[
        {"type":"cookie","pattern":"SymfonySession"}]},
    {"name":"CakePHP","category":"Framework","patterns":[
        {"type":"cookie","pattern":"cakephp"}]},
    {"name":"Slim","category":"Framework","patterns":[
        {"type":"header","pattern":"X-Powered-By: Slim"}]},

    # ═══ 数据库 / 缓存面板 ═══
    {"name":"phpRedisAdmin","category":"Database面板","patterns":[
        {"type":"html","pattern":"phpRedisAdmin"},
        {"type":"header","pattern":"phpRedisAdmin"}]},
    {"name":"Apache Druid","category":"监控","patterns":[
        {"type":"header","pattern":"Server: Apache-Druid"}]},
    {"name":"Apache Superset","category":"监控","patterns":[
        {"type":"html","pattern":"superset"}]},
    {"name":"Metabase","category":"监控","patterns":[
        {"type":"html","pattern":"metabase"}]},
    {"name":"Apache Airflow","category":"监控","patterns":[
        {"type":"html","pattern":"airflow"}]},
    {"name":"Apache Zeppelin","category":"监控","patterns":[
        {"type":"html","pattern":"zeppelin"}]},

    # ═══ 日志 / 消息队列 ═══
    {"name":"Kafka Manager","category":"监控","patterns":[
        {"type":"html","pattern":"kafka-manager"},
        {"type":"html","pattern":"CMAK"}]},
    {"name":"RabbitMQ Management","category":"监控","patterns":[
        {"type":"header","pattern":"Server: RabbitMQ"},
        {"type":"html","pattern":"rabbitmq"}]},
    {"name":"Logstash","category":"监控","patterns":[
        {"type":"header","pattern":"Server: Logstash"}]},
    {"name":"Fluentd","category":"监控","patterns":[
        {"type":"header","pattern":"Server: fluentd"}]},

    # ═══ API 网关 / 微服务 ═══
    {"name":"Kong","category":"Server","patterns":[
        {"type":"header","pattern":"Server: kong"}]},
    {"name":"APISIX","category":"Server","patterns":[
        {"type":"header","pattern":"Server: APISIX"}]},
    {"name":"Tyk","category":"Server","patterns":[
        {"type":"header","pattern":"Server: Tyk"}]},
    {"name":"Eureka","category":"监控","patterns":[
        {"type":"html","pattern":"eureka"}]},
    {"name":"Zookeeper","category":"监控","patterns":[
        {"type":"header","pattern":"Server: zookeeper"}]},
    {"name":"Consul","category":"监控","patterns":[
        {"type":"html","pattern":"consul"}]},
    {"name":"etcd","category":"监控","patterns":[
        {"type":"header","pattern":"Server: etcd"}]},
]

added = 0
for rule in NEW_RULES:
    if rule["name"].lower() not in existing:
        fps.append(rule)
        existing.add(rule["name"].lower())
        added += 1

with_ver = sum(1 for fp in fps for p in fp["patterns"] if "version" in p)
json.dump(fps, open(FP_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

# 统计分类
from collections import Counter
cats = Counter(fp["category"] for fp in fps)
print(f"新增 {added} 条，总计 {len(fps)} 条，带 version {with_ver} 条")
print("分类分布:")
for cat, n in cats.most_common():
    print(f"  {cat:20} {n}")
