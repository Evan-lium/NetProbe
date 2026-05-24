"""NetProbe CLI 入口。"""

import argparse
import sys
from datetime import datetime

import requests

from netprobe.engine import parse_targets, scan_all_targets
from netprobe.formatter import display_results, save_results
from netprobe.tools.registry import get_available_tools


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='NetProbe - 域名综合探测工具 (子域名发现 + 端口扫描 + Web探测)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='示例:\n'
               '  python main.py example.com\n'
               '  python main.py 93.184.216.34\n'
               '  python main.py example.com -o result.json -f json\n'
               '  python main.py example.com --no-dns-brute\n'
               '  python main.py example.com -w custom_wordlist.txt\n',
    )
    parser.add_argument('targets', nargs='+', help='目标域名或 IP，多个用空格分隔')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument(
        '-f', '--format',
        choices=['txt', 'csv', 'json'],
        default='txt',
        help='输出格式 (默认: txt)',
    )
    parser.add_argument('-w', '--wordlist', help='外部子域名字典文件')
    parser.add_argument('--no-validate', action='store_true', help='跳过 DNS 解析验证')
    parser.add_argument('--no-dns-brute', action='store_true', help='跳过子域名枚举')
    parser.add_argument('--no-web', action='store_true', help='跳过 Web 站点探测')
    parser.add_argument('--timeout', type=int, default=300, help='扫描超时秒数 (默认: 300)')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细过程')
    return parser


def main() -> None:
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )

    parser = build_parser()
    args = parser.parse_args()

    # 校验输入
    raw_input = ', '.join(args.targets)
    targets = parse_targets(raw_input)
    if not targets:
        print('[!] 未提供有效的扫描目标')
        sys.exit(1)

    # 报告可用工具
    tools = get_available_tools()
    avail = [v['label'] for v in tools.values() if v['available']]
    print(f'[*] 可用工具: {", ".join(avail) if avail else "无外部工具 (仅内置)"}')

    options = {
        'no_dns_brute': args.no_dns_brute,
        'no_web': args.no_web,
        'no_validate': args.no_validate,
        'timeout': args.timeout,
        'wordlist': args.wordlist,
    }

    def emit(event, **data):
        if event == 'progress':
            text = data.get('text', '')
            if '━━━' in text:
                print(f'\n{text}')
            else:
                print(f'[*] {text}')
        elif event == 'error':
            print(f'[!] {data.get("text", "")}')

    try:
        all_hosts = scan_all_targets(targets, options, emit)
    except KeyboardInterrupt:
        print('\n[!] 用户中断')
        sys.exit(130)

    if not all_hosts:
        print('[!] 所有目标均未获取到结果')
        sys.exit(1)

    # 显示结果
    for host in all_hosts:
        base = host.get('target', '')
        display_results([host], base)

    # 保存结果
    labels = list({h.get('hostname', '') for h in all_hosts})
    label = '+'.join(labels[:3])
    if len(labels) > 3:
        label += f'+{len(labels)-3}more'

    date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    fmt = args.format
    output_path = args.output if args.output else f'{label}_{date_str}.{fmt}'
    try:
        save_results(all_hosts, output_path, fmt, label)
        print(f'\n[*] 结果已保存到: {output_path}')
    except OSError as e:
        print(f'\n[!] 保存文件失败: {e}')


if __name__ == '__main__':
    main()
