#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import time
import random
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# === الألوان ===
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# === الواجهة الحمراء ===
def show_banner():
    banner = f"""{RED}
     .... NO! ...                  ... MNO! ...
   ..... MNO!! ...................... MNNOO! ...
 ..... MMNO! ......................... MNNOO!! .
.... MNOONNOO!   MMMMMMMMMMPPPOII!   MNNO!!!! .
 ... !O! NNO! MMMMMMMMMMMMMPPPOOOII!! NO! ....
    ...... ! MMMMMMMMMMMMMPPPPOOOOIII! ! ...
   ........ MMMMMMMMMMMMPPPPPOOOOOOII!! .....
   ........ MMMMMOOOOOOPPPPPPPPOOOOMII! ...
    ....... MMMMM..    OPPMMP    .,OMI! ....
     ...... MMMM::   o.,OPMP,.o   ::I!! ...
         .... NNM:::.,,OOPM!P,.::::!! ....
          .. MMNNNNNOOOOPMO!!IIPPO!!O! .....
         ... MMMMMNNNNOO:!!:!!IPPPPOO! ....
           .. MMMMMNNOOMMNNIIIPPPOO!! ......
          ...... MMMONNMMNNNIIIOO!..........
       ....... MN MOMMMNNNIIIIIO! OO ..........
    ......... MNO! IiiiiiiiiiiiI OOOO ...........
  ...... NNN.MNO! . O!!!!!!!!!O . OONO NO! ........
   .... MNNNNNO! ...OOOOOOOOOOO .  MMNNON!........
   ...... MNNNNO! .. PPPPPPPPP .. MMNON!........
      ...... OO! ................. ON! .......
         ................................{RESET}"""
    print(banner)

# === تحميل wordlist.txt ===
def load_wordlist():
    if not os.path.exists('wordlist.txt'):
        print(f"{RED}[-] Error: wordlist.txt not found!{RESET}")
        print(f"{YELLOW}[+] Creating sample wordlist.txt...{RESET}")
        sample_paths = [
            'admin', 'administrator', 'dashboard', 'controlpanel', 'api', 'api/v1',
            'internal', 'private', 'secret', 'backup', 'database', '.env',
            'config', 'settings', 'debug', 'logs', 'uploads', 'files',
            'user', 'users', 'account', 'profile', 'staff', 'wp-admin',
            'phpinfo.php', 'info.php', 'robots.txt', 'sitemap.xml'
        ]
        with open('wordlist.txt', 'w') as f:
            f.write('\n'.join(sample_paths))
        print(f"{GREEN}[+] Created sample wordlist.txt with 28 paths{RESET}")
    
    with open('wordlist.txt', 'r') as f:
        paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    return paths

# === تقنيات التلاعب (للاختيار 2) ===
def generate_bypass_variants(path):
    variants = set()
    variants.add(path)
    
    # Case manipulation
    variants.add(path.upper())
    variants.add(path.lower())
    variants.add(path.capitalize())
    
    # URL encoding
    from urllib.parse import quote
    variants.add(quote(path))
    variants.add(path.replace('/', '%2F'))
    variants.add(path.replace('.', '%2E'))
    
    # Double encoding
    variants.add(path.replace('/', '%252F'))
    
    # Path traversal
    variants.add(f"../{path}")
    variants.add(f"..%2F{path}")
    
    # Null byte
    variants.add(f"{path}%00")
    variants.add(f"{path}.php%00")
    
    # Parameter pollution
    variants.add(f"{path}?id=1")
    variants.add(f"{path}&debug=true")
    
    # File extensions
    for ext in ['.php', '.html', '.bak', '.old']:
        variants.add(f"{path}{ext}")
    
    # Trailing slash
    if path.endswith('/'):
        variants.add(path.rstrip('/'))
    else:
        variants.add(f"{path}/")
    
    return list(variants)

# === طلب المستخدم ===
def get_user_input(all_paths):
    print(f"\n{YELLOW}[+] Choose scan mode:{RESET}")
    print("1. Basic scan (no bypass)")
    print("2. Advanced scan (with bypass techniques)")
    
    while True:
        try:
            choice = int(input("\nEnter your choice (1 or 2): "))
            if choice in [1, 2]:
                break
            else:
                print(f"{RED}[-] Please enter 1 or 2{RESET}")
        except:
            print(f"{RED}[-] Invalid input{RESET}")
    
    total_paths = len(all_paths)
    print(f"\n{CYAN}[+] Total paths in wordlist.txt: {total_paths}{RESET}")
    
    while True:
        try:
            count = int(input(f"How many paths do you want to scan? (1-{total_paths}): "))
            if 1 <= count <= total_paths:
                break
            else:
                print(f"{RED}[-] Please enter a number between 1 and {total_paths}{RESET}")
        except:
            print(f"{RED}[-] Invalid number{RESET}")
    
    selected_paths = all_paths[:count]
    
    proxy_choice = input("\nDo you want to use proxies? (Y/n): ").strip().lower()
    use_proxy = proxy_choice != 'n'
    
    return choice, selected_paths, use_proxy

# === فحص مسار واحد ===
def test_path(target, path, use_bypass=False, use_proxy=False):
    results = []
    
    if use_bypass:
        variants = generate_bypass_variants(path)
    else:
        variants = [path]
    
    for variant in variants:
        url = urljoin(f"{target}/", variant.lstrip('/'))
        
        # Headers أساسية
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # إذا طلب بروكسي، سنستخدم واحدًا بسيطًا (في الإصدار الكامل يُضاف دعم بروكسي كامل)
        proxies = None
        if use_proxy:
            # في هذا الإصدار البسيط، نستخدم نفس الاتصال لكن مع هيدر وكيل
            headers['X-Forwarded-For'] = '127.0.0.1'
        
        try:
            resp = requests.get(url, headers=headers, timeout=8, proxies=proxies)
            
            # اكتشاف النتائج المهمة
            if resp.status_code == 200:
                results.append({
                    'url': url,
                    'status': resp.status_code,
                    'size': len(resp.content),
                    'method': 'GET'
                })
            elif resp.status_code in [301, 302, 307]:
                results.append({
                    'url': url,
                    'status': resp.status_code,
                    'size': len(resp.content),
                    'method': 'GET',
                    'location': resp.headers.get('Location', '')
                })
            elif resp.status_code == 403:
                # تحقق إذا كانت الصفحة تحتوي على محتوى إداري
                if any(keyword in resp.text.lower() for keyword in ['admin', 'dashboard', 'control']):
                    results.append({
                        'url': url,
                        'status': resp.status_code,
                        'size': len(resp.content),
                        'method': 'GET',
                        'note': 'Admin content in 403'
                    })
                    
        except:
            pass
    
    return results

# === عرض الجدول ===
def print_results_table(results):
    if not results:
        print(f"\n{RED}[-] No valid paths found.{RESET}")
        return
    
    print(f"\n{GREEN}" + "="*100 + f"{RESET}")
    print(f"{GREEN}{'URL':<50} {'STATUS':<8} {'SIZE':<10} {'METHOD':<8} {'NOTE':<20}{RESET}")
    print(f"{GREEN}" + "-"*100 + f"{RESET}")
    
    for result in results:
        url = result['url'][:47] + "..." if len(result['url']) > 50 else result['url']
        status = result['status']
        size = str(result['size'])
        method = result['method']
        note = result.get('note', result.get('location', ''))[:19]
        
        color = GREEN if status == 200 else YELLOW if status in [301, 302, 403] else RED
        print(f"{color}{url:<50} {status:<8} {size:<10} {method:<8} {note:<20}{RESET}")
    
    print(f"{GREEN}" + "="*100 + f"{RESET}")
    print(f"\n{CYAN}[+] Found {len(results)} valid paths.{RESET}")

# === التشغيل الرئيسي ===
def main():
    show_banner()
    
    target = input(f"\n{CYAN}Enter target URL (e.g., https://example.com): {RESET}").strip()
    if not target:
        print(f"{RED}[-] Target URL is required!{RESET}")
        sys.exit(1)
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    # تحميل wordlist
    all_paths = load_wordlist()
    if not all_paths:
        print(f"{RED}[-] No paths found in wordlist.txt!{RESET}")
        sys.exit(1)
    
    # الحصول على إعدادات المستخدم
    choice, selected_paths, use_proxy = get_user_input(all_paths)
    use_bypass = (choice == 2)
    
    print(f"\n{CYAN}[+] Starting scan on: {target}{RESET}")
    print(f"{CYAN}[+] Scan mode: {'Advanced (with bypass)' if use_bypass else 'Basic'}{RESET}")
    print(f"{CYAN}[+] Paths to scan: {len(selected_paths)}{RESET}")
    print(f"{CYAN}[+] Proxy usage: {'Enabled' if use_proxy else 'Disabled'}{RESET}")
    print(f"{YELLOW}\n[!] Scanning... This may take several minutes.{RESET}")
    
    # التنفيذ المتوازي
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_path = {
            executor.submit(test_path, target, path, use_bypass, use_proxy): path 
            for path in selected_paths
        }
        
        for future in as_completed(future_to_path):
            try:
                result = future.result()
                results.extend(result)
            except:
                pass
    
    # عرض النتائج
    print_results_table(results)
    
    # حفظ النتائج
    if results:
        with open('idor_results.txt', 'w') as f:
            for result in results:
                f.write(f"{result['url']} | {result['status']} | {result['size']}\n")
        print(f"\n{GREEN}[+] Results saved to: idor_results.txt{RESET}")

if __name__ == "__main__":
    main()

