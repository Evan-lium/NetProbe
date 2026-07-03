"""NetProbe CLI 入口。"""

import argparse
import sys
from datetime import datetime

import requests

from netprobe.engine import parse_targets, scan_all_targets
from netprobe.formatter import display_results, save_results
from netprobe.tools.registry import get_available_tools
from netprobe.risk import risk_level


def _add_common_scan_args(parser: argparse.ArgumentParser):
    """给子命令添加共用的扫描参数。"""
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument(
        '-f', '--format',
        choices=['txt', 'csv', 'json', 'html'],
        default='txt',
        help='输出格式 (默认: txt)',
    )
    parser.add_argument('-w', '--wordlist', help='外部子域名字典文件')
    parser.add_argument('--no-validate', action='store_true', help='跳过 DNS 解析验证')
    parser.add_argument('--no-dns-brute', action='store_true', help='跳过子域名枚举')
    parser.add_argument('--no-web', action='store_true', help='跳过 Web 站点探测')
    parser.add_argument('--timeout', type=int, default=300, help='扫描超时秒数 (默认: 300)')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细过程')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='NetProbe - 域名综合探测工具 (子域名发现 + 端口扫描 + Web探测)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='示例:\n'
               '  python main.py example.com\n'
               '  python main.py example.com -o result.json -f json\n'
               '  python main.py scan example.com --no-dns-brute\n'
               '  python main.py ci example.com --severity-threshold 70\n',
    )
    subparsers = parser.add_subparsers(dest='command')

    # 默认扫描（保持向后兼容：python main.py example.com）
    scan_parser = subparsers.add_parser('scan', help='执行扫描（默认行为）')
    scan_parser.add_argument('targets', nargs='+', help='目标域名或 IP')
    _add_common_scan_args(scan_parser)

    # CI/CD 模式
    ci_parser = subparsers.add_parser('ci', help='CI/CD 模式：发现高危资产时退出码非零')
    ci_parser.add_argument('targets', nargs='+', help='目标域名或 IP')
    ci_parser.add_argument(
        '--severity-threshold', type=int, default=70,
        help='风险分阈值，>=此值视为高危并退出码 1 (默认: 70)',
    )
    ci_parser.add_argument(
        '--fail-on', default='high_risk',
        choices=['high_risk', 'sensitive', 'any'],
        help='失败条件: high_risk(风险分超阈值) / sensitive(有高危敏感路径) / any(任何发现)',
    )
    _add_common_scan_args(ci_parser)

    return parser


def _make_emit(verbose: bool = False):
    """构造进度回调。"""
    def emit(event, **data):
        if event == 'progress':
            text = data.get('text', '')
            if '━━━' in text:
                print(f'\n{text}')
            else:
                print(f'[*] {text}')
        elif event == 'error':
            print(f'[!] {data.get("text", "")}')
    return emit


def _build_options(args) -> dict:
    """从 argparse 参数构造扫描 options dict。"""
    return {
        'no_dns_brute': args.no_dns_brute,
        'no_web': args.no_web,
        'no_validate': args.no_validate,
        'timeout': args.timeout,
        'wordlist': args.wordlist,
    }


def _run_scan_and_report(args, options, emit):
    """执行扫描 + 显示 + 保存结果，返回 all_hosts。"""
    all_hosts = scan_all_targets(
        parse_targets(', '.join(args.targets)), options, emit
    )
    if not all_hosts:
        return []

    for host in all_hosts:
        base = host.get('target', '')
        display_results([host], base)

    labels = list({h.get('hostname', '') for h in all_hosts})
    label = '+'.join(labels[:3])
    if len(labels) > 3:
        label += f'+{len(labels) - 3}more'

    date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    fmt = args.format
    output_path = args.output if args.output else f'{label}_{date_str}.{fmt}'
    try:
        save_results(all_hosts, output_path, fmt, label)
        print(f'\n[*] 结果已保存到: {output_path}')
    except OSError as e:
        print(f'\n[!] 保存文件失败: {e}')

    return all_hosts


def _run_ci(args, options, emit) -> int:
    """CI/CD 模式：扫描后按条件判定退出码。

    退出码: 0=clean, 1=发现高危, 2=扫描异常
    """
    print('[CI] NetProbe CI/CD 模式启动')
    print(f'[CI] 失败条件: {args.fail_on}, 阈值: {args.severity_threshold}')

    try:
        all_hosts = scan_all_targets(
            parse_targets(', '.join(args.targets)), options, emit
        )
    except KeyboardInterrupt:
        print('\n[CI] 用户中断')
        return 2
    except Exception as e:
        print(f'[CI] 扫描异常: {e}')
        return 2

    if not all_hosts:
        print('[CI] 无扫描结果，退出码 0')
        return 0

    # 判定是否命中失败条件
    should_fail = False
    high_risk_hosts = []
    sensitive_hosts = []

    for host in all_hosts:
        score = host.get('risk_score', 0)
        if score >= args.severity_threshold:
            high_risk_hosts.append((host.get('hostname', ''), score))

        for s in host.get('sensitive', []):
            if (s.get('severity') or '').lower() in ('high', 'critical'):
                sensitive_hosts.append((host.get('hostname', ''), s.get('path', '')))
                break

    if args.fail_on == 'high_risk' and high_risk_hosts:
        should_fail = True
        print(f'\n[CI] ✗ 发现 {len(high_risk_hosts)} 个高危主机(风险分 >= {args.severity_threshold}):')
        for name, score in high_risk_hosts:
            print(f'    - {name}: {score} 分')
    elif args.fail_on == 'sensitive' and sensitive_hosts:
        should_fail = True
        print(f'\n[CI] ✗ 发现 {len(sensitive_hosts)} 个含高危敏感路径的主机:')
        for name, path in sensitive_hosts[:10]:
            print(f'    - {name}: {path}')
    elif args.fail_on == 'any' and (high_risk_hosts or sensitive_hosts):
        should_fail = True
        print(f'\n[CI] ✗ 发现安全风险 ({len(high_risk_hosts)} 高危主机, {len(sensitive_hosts)} 敏感路径)')

    # 输出摘要
    total = len(all_hosts)
    avg_risk = sum(h.get('risk_score', 0) for h in all_hosts) // total if total else 0
    print(f'\n[CI] 扫描摘要: {total} 台主机, 平均风险分 {avg_risk}')

    if should_fail:
        print('[CI] 结果: FAIL (退出码 1)')
        return 1
    print('[CI] 结果: PASS (退出码 0)')
    return 0


def main() -> None:
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )

    parser = build_parser()
    args = parser.parse_args()

    # 无子命令时，把整体 args 当作 scan 处理（向后兼容: python main.py example.com）
    if not args.command:
        # 重建为 scan 语义：targets 是位置参数
        if not hasattr(args, 'targets') or not args.targets:
            parser.print_help()
            sys.exit(1)
        args.command = 'scan'

    if args.command == 'scan':
        targets = parse_targets(', '.join(args.targets))
        if not targets:
            print('[!] 未提供有效的扫描目标')
            sys.exit(1)

        tools = get_available_tools()
        avail = [v['label'] for v in tools.values() if v['available']]
        print(f'[*] 可用工具: {", ".join(avail) if avail else "无外部工具 (仅内置)"}')

        options = _build_options(args)
        emit = _make_emit(getattr(args, 'verbose', False))

        try:
            _run_scan_and_report(args, options, emit)
        except KeyboardInterrupt:
            print('\n[!] 用户中断')
            sys.exit(130)

    elif args.command == 'ci':
        targets = parse_targets(', '.join(args.targets))
        if not targets:
            print('[CI] 未提供有效的扫描目标')
            sys.exit(2)

        tools = get_available_tools()
        avail = [v['label'] for v in tools.values() if v['available']]
        print(f'[CI] 可用工具: {", ".join(avail) if avail else "无外部工具 (仅内置)"}')

        options = _build_options(args)
        emit = _make_emit(getattr(args, 'verbose', False))

        exit_code = _run_ci(args, options, emit)
        sys.exit(exit_code)


if __name__ == '__main__':
    main()
