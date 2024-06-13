import requests
import socket
import ssl
import pandas as pd


def check_http_headers(headers):
    # 检查 HTTP 响应头中的宝塔特征
    if 'Server' in headers and 'bt.cn' in headers['Server']:
        return True
    if 'X-Powered-By' in headers and 'bt.cn' in headers['X-Powered-By']:
        return True
    return False


def check_http_content(content):
    # 检查 HTTP 响应内容中的宝塔特征
    if '宝塔安全页' in content or 'bt.cn' in content:
        return True
    return False


def check_ssl_certificate(domain_or_ip):
    try:
        # 获取 SSL 证书信息
        context = ssl.create_default_context()
        with socket.create_connection((domain_or_ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain_or_ip) as ssock:
                cert = ssock.getpeercert()
                if 'bt.cn' in str(cert):
                    return True
    except Exception:
        pass
    return False


def check_specific_port(domain_or_ip, port):
    try:
        # 检查特定端口是否开放
        with socket.create_connection((domain_or_ip, port), timeout=5):
            return True
    except Exception:
        pass
    return False


def check_baota_firewall(domain_or_ip):
    try:
        # 发送 HTTP 请求
        response = requests.get(f'http://{domain_or_ip}', timeout=5)

        # 检查 HTTP 响应头和内容
        if check_http_headers(response.headers) or check_http_content(response.text):
            return True
    except requests.RequestException:
        pass

    # 检查 SSL 证书
    if check_ssl_certificate(domain_or_ip):
        return True

    # 检查特定端口（如 8888 和 888）
    if check_specific_port(domain_or_ip, 8888) or check_specific_port(domain_or_ip, 888):
        return True

    return False


# 从文件读取 URL 列表
def read_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]


# 读取 urls.txt 文件中的 URL 列表
urls_file = 'urls.txt'
domains_or_ips = read_urls_from_file(urls_file)

# 批量检查
results = []

for item in domains_or_ips:
    result = {
        'Domain/IP': item,
        'Uses Baota Firewall': check_baota_firewall(item)
    }
    results.append(result)

# 创建 DataFrame
df = pd.DataFrame(results)

# 导出到 Excel 文件
output_file = 'baota_firewall_check_results.xlsx'
df.to_excel(output_file, index=False)

print(f'Results have been written to {output_file}')
