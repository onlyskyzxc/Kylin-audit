#!/usr/bin/env python3
"""
麒麟操作系统等级保护安全配置核查脚本（完整版）
包含：身份鉴别、访问控制、安全审计、入侵防范、恶意代码防护、数据完整性、数据保密性、剩余信息保护
特别补充：登录超时检查、多余账户检查、命令历史记录检查
修复：主机名清理，避免文件名包含非法字符
"""

import os
import sys
import re
import json
import time
import socket
import argparse
import getpass
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

# 尝试导入所需库
try:
    import paramiko
    from paramiko.ssh_exception import SSHException, AuthenticationException
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("警告: paramiko库未安装，将无法进行SSH连接")
    print("安装命令: pip install paramiko")

try:
    import jinja2
    TEMPLATE_AVAILABLE = True
except ImportError:
    TEMPLATE_AVAILABLE = False
    print("警告: jinja2库未安装，HTML报告模板功能受限")
    print("安装命令: pip install jinja2")

# 颜色代码
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class SSHClient:
    """SSH客户端封装类"""
    
    def __init__(self, host: str, port: int = 22, username: str = None, 
                 password: str = None, key_file: str = None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.client = None
        self.connected = False
        
    def connect(self) -> bool:
        """连接到SSH服务器"""
        if not SSH_AVAILABLE:
            print(f"{Colors.RED}错误: paramiko库未安装{Colors.END}")
            return False
            
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # 尝试不同的认证方式
            if self.key_file and os.path.exists(self.key_file):
                # 使用密钥认证
                print(f"{Colors.CYAN}尝试使用密钥认证...{Colors.END}")
                try:
                    key = paramiko.RSAKey.from_private_key_file(self.key_file)
                    self.client.connect(
                        self.host, self.port, self.username,
                        pkey=key, timeout=10
                    )
                except SSHException as e:
                    print(f"{Colors.YELLOW}密钥认证失败: {e}{Colors.END}")
                    if self.password:
                        print(f"{Colors.CYAN}尝试使用密码认证...{Colors.END}")
                        self.client.connect(
                            self.host, self.port, self.username,
                            password=self.password, timeout=10
                        )
                    else:
                        raise
            elif self.password:
                # 使用密码认证
                print(f"{Colors.CYAN}尝试使用密码认证...{Colors.END}")
                self.client.connect(
                    self.host, self.port, self.username,
                    password=self.password, timeout=10
                )
            else:
                # 尝试无密码连接（可能已配置免密登录）
                print(f"{Colors.CYAN}尝试无密码连接...{Colors.END}")
                self.client.connect(
                    self.host, self.port, self.username,
                    timeout=10
                )
            
            self.connected = True
            print(f"{Colors.GREEN}✓ SSH连接成功{Colors.END}")
            return True
            
        except AuthenticationException:
            print(f"{Colors.RED}认证失败，请检查用户名/密码/密钥{Colors.END}")
            return False
        except SSHException as e:
            print(f"{Colors.RED}SSH连接失败: {e}{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.RED}连接错误: {e}{Colors.END}")
            return False
    
    def execute(self, command: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """执行命令并返回结果"""
        if not self.connected:
            return False, "", "未连接"
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            
            return exit_code == 0, output, error
            
        except Exception as e:
            return False, "", f"执行错误: {str(e)}"
    
    def close(self):
        """关闭连接"""
        if self.client:
            self.client.close()
            self.connected = False

class SecurityAuditor:
    """安全配置核查器"""
    
    def __init__(self, ssh_client: SSHClient):
        self.ssh = ssh_client
        self.results = {
            "identity": [],      # 身份鉴别
            "access_control": [], # 访问控制
            "security_audit": [], # 安全审计
            "intrusion": [],     # 入侵防范
            "malware": [],       # 恶意代码防护
            "data_integrity": [], # 数据完整性
            "data_confidentiality": [], # 数据保密性
            "residual_info": []  # 剩余信息保护
        }
        self.system_info = {}
        
    def _clean_hostname(self, raw: str) -> str:
        """清理主机名，只保留合法字符"""
        if not raw:
            return 'unknown'
        # 只允许字母、数字、点、连字符、下划线，其余替换为 '_'
        cleaned = re.sub(r'[^a-zA-Z0-9._-]', '_', raw.strip())
        # 限制长度，避免过长文件名
        cleaned = cleaned[:64] if cleaned else 'unknown'
        # 如果清理后全是'_'或空，则返回'unknown'
        if cleaned.strip('_') == '':
            return 'unknown'
        return cleaned

    def gather_system_info(self):
        """收集系统信息（增强主机名清理）"""
        print(f"{Colors.BLUE}收集系统信息...{Colors.END}")
        
        # 获取主机名（多种备选）
        hostname = 'unknown'
        for cmd in ["hostname", "uname -n"]:
            success, output, _ = self.ssh.execute(cmd)
            if success and output:
                cleaned = self._clean_hostname(output)
                if cleaned != 'unknown':
                    hostname = cleaned
                    break
        self.system_info['hostname'] = hostname
        
        # 获取操作系统信息
        success, output, error = self.ssh.execute(
            "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'"
        )
        self.system_info['os'] = output if success else "未知"
        
        # 获取内核版本
        success, output, error = self.ssh.execute("uname -r")
        self.system_info['kernel'] = output if success else "未知"
        
        # 获取IP地址
        success, output, error = self.ssh.execute(
            "hostname -I 2>/dev/null | awk '{print $1}'"
        )
        self.system_info['ip'] = output if success else "未知"
        
        # 获取系统架构
        success, output, error = self.ssh.execute("uname -m")
        self.system_info['arch'] = output if success else "未知"
        
        print(f"{Colors.GREEN}主机名: {self.system_info['hostname']}{Colors.END}")
        print(f"{Colors.GREEN}操作系统: {self.system_info['os']}{Colors.END}")
        print(f"{Colors.GREEN}内核版本: {self.system_info['kernel']}{Colors.END}")
        print(f"{Colors.GREEN}IP地址: {self.system_info['ip']}{Colors.END}")
    
    def add_result(self, category: str, title: str, command: str, 
                   output: str, status: str, details: str = ""):
        """添加检查结果"""
        result = {
            "title": title,
            "command": command,
            "output": output,
            "status": status,  # pass, fail, warning, info
            "details": details,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
        
        if category in self.results:
            self.results[category].append(result)
        else:
            print(f"警告: 未知的分类 {category}")
    
    def check_identity(self):
        """检查身份鉴别（包含登录连接超时检查）"""
        print(f"\n{Colors.BLUE}[1/8] 检查身份鉴别...{Colors.END}")
        
        # 1.1 密码复杂度策略
        success, output, error = self.ssh.execute(
            "cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^$'"
        )
        if success and output:
            if "minlen = 8" in output and "minclass = 3" in output:
                status = "pass"
                details = "密码复杂度策略符合要求（最小长度8位，包含3种字符类型）"
            else:
                status = "fail"
                details = "密码复杂度策略不符合要求"
        else:
            status = "fail"
            output = "文件不存在或无法读取"
            details = "密码复杂度策略未配置"
        
        self.add_result("identity", "1.1 密码复杂度策略", 
                       "cat /etc/security/pwquality.conf", 
                       output, status, details)
        
        # 1.2 密码有效期
        success, output, error = self.ssh.execute(
            "cat /etc/login.defs 2>/dev/null | grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE'"
        )
        if success and output:
            if "PASS_MAX_DAYS\t90" in output or "PASS_MAX_DAYS 90" in output:
                status = "pass"
                details = "密码有效期设置符合要求（90天）"
            else:
                status = "warning"
                details = "密码有效期设置可能需要调整"
        else:
            status = "info"
            details = "密码有效期设置未找到"
        
        self.add_result("identity", "1.2 密码有效期设置", 
                       "cat /etc/login.defs | grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE'", 
                       output, status, details)
        
        # 1.3 登录失败处理
        success, output, error = self.ssh.execute(
            "cat /etc/pam.d/system-auth 2>/dev/null | grep -E 'pam_tally|pam_faillock'"
        )
        if success and output:
            if "deny=5" in output or "unlock_time=900" in output:
                status = "pass"
                details = "登录失败处理机制已配置"
            else:
                status = "warning"
                details = "登录失败处理机制可能需要配置"
        else:
            status = "info"
            details = "登录失败处理机制未找到"
        
        self.add_result("identity", "1.3 登录失败处理机制", 
                       "cat /etc/pam.d/system-auth | grep -E 'pam_tally|pam_faillock'", 
                       output, status, details)
        
        # 1.4 SSH配置检查
        success, output, error = self.ssh.execute(
            "cat /etc/ssh/sshd_config 2>/dev/null | grep -E 'PermitRootLogin|PasswordAuthentication|Protocol' | grep -v '^#'"
        )
        if success:
            if "PermitRootLogin no" in output and "Protocol 2" in output:
                status = "pass"
                details = "SSH配置符合安全要求"
            else:
                status = "warning"
                details = "SSH配置需要检查"
        else:
            status = "fail"
            details = "SSH配置文件无法读取"
        
        self.add_result("identity", "1.4 SSH安全配置", 
                       "cat /etc/ssh/sshd_config | grep -E 'PermitRootLogin|PasswordAuthentication|Protocol'", 
                       output, status, details)
        
        # 1.5 空密码账户检查
        success, output, error = self.ssh.execute(
            "awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow 2>/dev/null"
        )
        if success:
            if output:
                status = "fail"
                details = f"发现空密码账户: {output}"
            else:
                status = "pass"
                details = "未发现空密码账户"
        else:
            status = "warning"
            details = "无法检查空密码账户"
        
        self.add_result("identity", "1.5 空密码账户检查", 
                       "awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow", 
                       output, status, details)
        
        # 1.6 登录连接超时自动退出功能检查（新增）
        print(f"{Colors.CYAN}  检查登录连接超时配置...{Colors.END}")
        
        # 1.6.1 SSH登录超时配置
        success, output, error = self.ssh.execute(
            "cat /etc/ssh/sshd_config 2>/dev/null | grep -E 'ClientAliveInterval|ClientAliveCountMax' | grep -v '^#'"
        )
        
        ssh_timeout_configured = False
        if success and output:
            lines = output.strip().split('\n')
            client_alive_interval = None
            client_alive_count_max = None
            
            for line in lines:
                if 'ClientAliveInterval' in line:
                    try:
                        client_alive_interval = int(line.split()[-1])
                    except:
                        pass
                elif 'ClientAliveCountMax' in line:
                    try:
                        client_alive_count_max = int(line.split()[-1])
                    except:
                        pass
            
            if client_alive_interval is not None and client_alive_count_max is not None:
                total_timeout = client_alive_interval * client_alive_count_max
                if total_timeout <= 900:  # 15分钟
                    ssh_timeout_configured = True
                    details = f"SSH超时配置符合要求（ClientAliveInterval={client_alive_interval}, ClientAliveCountMax={client_alive_count_max}）"
                    status = "pass"
                else:
                    details = f"SSH超时时间过长（{total_timeout}秒），建议不超过900秒"
                    status = "warning"
            else:
                details = "SSH超时配置不完整或未配置"
                status = "fail"
        else:
            details = "SSH超时配置未设置"
            status = "fail"
        
        self.add_result("identity", "1.6.1 SSH登录超时配置", 
                       "cat /etc/ssh/sshd_config | grep -E 'ClientAliveInterval|ClientAliveCountMax'", 
                       output, status, details)
        
        # 1.6.2 Shell会话超时配置
        success, output, error = self.ssh.execute(
            "echo $TMOUT 2>/dev/null && grep -r 'TMOUT' /etc/profile /etc/bashrc /etc/profile.d/* 2>/dev/null | grep -v '^#'"
        )
        
        shell_timeout_configured = False
        if success:
            if output:
                lines = output.strip().split('\n')
                tmout_value = None
                
                for line in lines:
                    if 'TMOUT=' in line:
                        try:
                            tmout_match = re.search(r'TMOUT\s*=\s*(\d+)', line)
                            if tmout_match:
                                tmout_value = int(tmout_match.group(1))
                        except:
                            pass
                    elif line.isdigit():
                        tmout_value = int(line)
                
                if tmout_value is not None and tmout_value <= 900:  # 15分钟
                    shell_timeout_configured = True
                    details = f"Shell超时配置符合要求（TMOUT={tmout_value}秒）"
                    status = "pass"
                else:
                    if tmout_value:
                        details = f"Shell超时时间过长（{tmout_value}秒），建议不超过900秒"
                    else:
                        details = "Shell超时配置不明确"
                    status = "warning"
            else:
                details = "Shell超时配置未设置"
                status = "warning"
        else:
            details = "无法检查Shell超时配置"
            status = "info"
        
        self.add_result("identity", "1.6.2 Shell会话超时配置", 
                       "echo $TMOUT && grep -r 'TMOUT' /etc/profile /etc/bashrc /etc/profile.d/*", 
                       output, status, details)
        
        # 1.6.3 su/sudo会话超时配置
        success, output, error = self.ssh.execute(
            "grep -r 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#'"
        )
        
        sudo_timeout_configured = False
        if success and output:
            lines = output.strip().split('\n')
            sudo_timeout = None
            
            for line in lines:
                if 'timestamp_timeout' in line:
                    try:
                        # 提取超时值，支持正数、负数、0
                        match = re.search(r'timestamp_timeout\s*=\s*(-?\d+)', line)
                        if match:
                            sudo_timeout = int(match.group(1))
                    except:
                        pass
            
            if sudo_timeout is not None:
                if sudo_timeout >= 0 and sudo_timeout <= 15:  # 0-15分钟
                    sudo_timeout_configured = True
                    details = f"sudo超时配置符合要求（timestamp_timeout={sudo_timeout}）"
                    status = "pass"
                elif sudo_timeout == -1:
                    details = "sudo会话永不过期，存在安全风险"
                    status = "fail"
                else:
                    details = f"sudo超时时间过长（{sudo_timeout}分钟），建议不超过15分钟"
                    status = "warning"
            else:
                details = "sudo超时配置未找到"
                status = "info"
        else:
            details = "sudo超时配置未设置（使用默认值）"
            status = "info"
        
        self.add_result("identity", "1.6.3 sudo会话超时配置", 
                       "grep -r 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/*", 
                       output, status, details)
        
        # 1.6.4 登录超时配置总结
        if ssh_timeout_configured and shell_timeout_configured:
            summary_status = "pass"
            summary_details = "登录连接超时配置完整且符合要求"
        elif ssh_timeout_configured or shell_timeout_configured:
            summary_status = "warning"
            summary_details = "部分登录超时配置已设置，建议完善所有配置"
        else:
            summary_status = "fail"
            summary_details = "登录超时配置缺失，存在安全风险"
        
        self.add_result("identity", "1.6.4 登录超时配置总结", 
                       "N/A (综合检查结果)", 
                       f"SSH超时: {'已配置' if ssh_timeout_configured else '未配置'}, Shell超时: {'已配置' if shell_timeout_configured else '未配置'}, sudo超时: {'已配置' if sudo_timeout_configured else '未配置'}", 
                       summary_status, summary_details)
    
    def check_access_control(self):
        """检查访问控制（包含多余账户检查）"""
        print(f"\n{Colors.BLUE}[2/8] 检查访问控制...{Colors.END}")
        
        # 2.1 关键文件权限
        success, output, error = self.ssh.execute(
            "ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null"
        )
        if success:
            lines = output.split('\n')
            passwd_ok = any('-rw-r--r--' in line and '/etc/passwd' in line for line in lines)
            shadow_ok = any('----------' in line and '/etc/shadow' in line for line in lines)
            
            if passwd_ok and shadow_ok:
                status = "pass"
                details = "关键文件权限设置正确"
            else:
                status = "fail"
                details = "关键文件权限设置不正确"
        else:
            status = "warning"
            details = "无法检查文件权限"
        
        self.add_result("access_control", "2.1 关键文件权限检查", 
                       "ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow", 
                       output, status, details)
        
        # 2.2 sudo权限配置
        success, output, error = self.ssh.execute(
            "cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | head -10"
        )
        if success:
            if "NOPASSWD:" in output:
                status = "warning"
                details = "发现无需密码的sudo权限，建议检查"
            else:
                status = "pass"
                details = "sudo权限配置合理"
        else:
            status = "info"
            details = "sudo配置无法读取"
        
        self.add_result("access_control", "2.2 sudo权限配置", 
                       "cat /etc/sudoers | grep -v '^#' | grep -v '^$'", 
                       output, status, details)
        
        # 2.3 umask设置
        success, output, error = self.ssh.execute(
            "umask && grep -E 'umask.*[0-9]{3}' /etc/bashrc /etc/profile 2>/dev/null"
        )
        if success:
            if "027" in output or "022" in output:
                status = "pass"
                details = "umask设置符合安全要求"
            else:
                status = "warning"
                details = "umask设置可能过于宽松"
        else:
            status = "info"
        
        self.add_result("access_control", "2.3 umask默认权限", 
                       "umask && grep -E 'umask.*[0-9]{3}' /etc/bashrc /etc/profile", 
                       output, status, details)
        
        # 2.4 不必要的服务
        success, output, error = self.ssh.execute(
            "systemctl list-unit-files 2>/dev/null | grep enabled | "
            "grep -E '(ftp|telnet|rsh|rlogin|rexec|nfs|ypbind)' || echo '未发现'"
        )
        if success and output != "未发现":
            status = "warning"
            details = "发现不安全的服务正在运行"
        else:
            status = "pass"
            details = "未发现不安全的服务"
        
        self.add_result("access_control", "2.4 不必要的服务检查", 
                       "systemctl list-unit-files | grep enabled | grep -E '(ftp|telnet|rsh|rlogin|rexec|nfs|ypbind)'", 
                       output, status, details)
        
        # 2.5 多余账户检查（新增）
        print(f"{Colors.CYAN}  检查多余账户...{Colors.END}")
        
        # 2.5.1 检查UID为0的多余账户
        success, output, error = self.ssh.execute(
            "awk -F: '($3 == 0) {print $1}' /etc/passwd"
        )
        if success:
            root_users = output.strip().split('\n') if output else []
            if len(root_users) == 1 and root_users[0] == 'root':
                status = "pass"
                details = "只有root用户的UID为0"
            else:
                status = "fail"
                details = f"发现多个UID为0的用户: {', '.join(root_users)}"
        else:
            status = "warning"
            details = "无法检查UID为0的用户"
        
        self.add_result("access_control", "2.5.1 UID为0的多余账户", 
                       "awk -F: '($3 == 0) {print $1}' /etc/passwd", 
                       output, status, details)
        
        # 2.5.2 检查系统账户和用户账户
        success, output, error = self.ssh.execute(
            "awk -F: '($3 < 1000) {print \"系统账户:\" $1 \":\" $3} ($3 >= 1000) {print \"用户账户:\" $1 \":\" $3}' /etc/passwd | sort"
        )
        if success:
            lines = output.strip().split('\n') if output else []
            system_accounts = []
            user_accounts = []
            
            for line in lines:
                if line.startswith('系统账户:'):
                    system_accounts.append(line.split(':')[1])
                elif line.startswith('用户账户:'):
                    user_accounts.append(line.split(':')[1])
            
            system_count = len(system_accounts)
            user_count = len(user_accounts)
            
            if system_count <= 30:  # 正常系统账户数量
                status = "pass"
                details = f"系统账户数量正常（{system_count}个）"
            else:
                status = "warning"
                details = f"系统账户数量较多（{system_count}个），可能存在多余账户"
            
            # 同时记录用户账户数量供参考
            details += f"，用户账户：{user_count}个"
        else:
            status = "info"
            details = "无法检查账户分类"
        
        self.add_result("access_control", "2.5.2 系统账户和用户账户", 
                       "awk -F: '($3 < 1000) {print \"系统账户:\" $1 \":\" $3} ($3 >= 1000) {print \"用户账户:\" $1 \":\" $3}' /etc/passwd", 
                       output, status, details)
        
        # 2.5.3 检查长期未登录的账户
        success, output, error = self.ssh.execute(
            "lastlog 2>/dev/null | grep -v \"Never logged in\" | grep -v \"Username\" | head -10"
        )
        if success and output:
            lines = output.strip().split('\n')
            recent_logins = []
            
            for line in lines:
                if line:
                    parts = line.split()
                    if len(parts) >= 4:
                        username = parts[0]
                        # 尝试解析登录时间
                        recent_logins.append(username)
            
            if recent_logins:
                details = f"最近登录用户: {', '.join(recent_logins[:5])}"
                if len(recent_logins) > 5:
                    details += f" 等{len(recent_logins)}个用户"
                status = "info"
            else:
                details = "未找到最近登录记录"
                status = "info"
        else:
            details = "无法检查登录记录或所有用户都未登录过"
            status = "info"
        
        self.add_result("access_control", "2.5.3 最近登录用户检查", 
                       "lastlog | grep -v \"Never logged in\" | grep -v \"Username\"", 
                       output, status, details)
        
        # 2.5.4 检查可登录的Shell账户
        success, output, error = self.ssh.execute(
            "grep -E \"/bin/(bash|sh|ksh|csh|tcsh|zsh)$\" /etc/passwd | cut -d: -f1 | sort"
        )
        if success:
            shells = output.strip().split('\n') if output else []
            if shells:
                details = f"可登录Shell的账户: {', '.join(shells[:10])}"
                if len(shells) > 10:
                    details += f" 等{len(shells)}个账户"
                status = "info"
            else:
                details = "未找到可登录Shell的账户"
                status = "warning"
        else:
            details = "无法检查可登录Shell账户"
            status = "info"
        
        self.add_result("access_control", "2.5.4 可登录Shell账户", 
                       "grep -E \"/bin/(bash|sh|ksh|csh|tcsh|zsh)$\" /etc/passwd | cut -d: -f1", 
                       output, status, details)
        
        # 2.5.5 检查无密码账户（再次确认）
        success, output, error = self.ssh.execute(
            "awk -F: '($2 == \"\") {print \"无密码:\" $1} ($2 == \"!\") {print \"锁定:\" $1} ($2 == \"!!\") {print \"未设置:\" $1}' /etc/shadow"
        )
        if success and output:
            lines = output.strip().split('\n')
            no_password = []
            locked = []
            not_set = []
            
            for line in lines:
                if line.startswith('无密码:'):
                    no_password.append(line.split(':')[1])
                elif line.startswith('锁定:'):
                    locked.append(line.split(':')[1])
                elif line.startswith('未设置:'):
                    not_set.append(line.split(':')[1])
            
            if no_password:
                status = "fail"
                details = f"发现无密码账户: {', '.join(no_password)}"
            elif not_set:
                status = "warning"
                details = f"发现未设置密码账户: {', '.join(not_set)}"
            else:
                status = "pass"
                details = "未发现无密码账户"
                
            if locked:
                details += f"，锁定账户: {len(locked)}个"
        else:
            status = "pass"
            details = "未发现无密码账户"
        
        self.add_result("access_control", "2.5.5 账户密码状态检查", 
                       "awk -F: '($2 == \"\") {print \"无密码:\" $1} ($2 == \"!\") {print \"锁定:\" $1} ($2 == \"!!\") {print \"未设置:\" $1}' /etc/shadow", 
                       output, status, details)
    
    def check_security_audit(self):
        """检查安全审计"""
        print(f"\n{Colors.BLUE}[3/8] 检查安全审计...{Colors.END}")
        
        # 3.1 审计服务状态
        success, output, error = self.ssh.execute(
            "systemctl status auditd --no-pager 2>/dev/null || echo '审计服务未安装'"
        )
        if success:
            if "active (running)" in output:
                status = "pass"
                details = "审计服务正在运行"
            else:
                status = "warning"
                details = "审计服务未运行或未安装"
        else:
            status = "info"
        
        self.add_result("security_audit", "3.1 审计服务状态", 
                       "systemctl status auditd --no-pager", 
                       output, status, details)
        
        # 3.2 审计规则
        success, output, error = self.ssh.execute(
            "auditctl -l 2>/dev/null || echo '审计工具未安装'"
        )
        if success:
            if output and "审计工具未安装" not in output:
                status = "pass"
                details = "审计规则已配置"
            else:
                status = "warning"
                details = "审计规则未配置"
        else:
            status = "info"
        
        self.add_result("security_audit", "3.2 审计规则检查", 
                       "auditctl -l", output, status, details)
        
        # 3.3 系统日志配置
        success, output, error = self.ssh.execute(
            "cat /etc/rsyslog.conf 2>/dev/null | grep -E 'auth|authpriv|\\*\\..\\*/var/log' | grep -v '^#'"
        )
        if success:
            if output:
                status = "pass"
                details = "系统日志配置完整"
            else:
                status = "warning"
                details = "系统日志配置不完整"
        else:
            status = "info"
        
        self.add_result("security_audit", "3.3 系统日志配置", 
                       "cat /etc/rsyslog.conf | grep -E 'auth|authpriv|\\*\\..\\*/var/log'", 
                       output, status, details)
        
        # 3.4 日志轮转
        success, output, error = self.ssh.execute(
            "ls -l /etc/logrotate.d/syslog 2>/dev/null || echo '未找到配置文件'"
        )
        if success and "未找到配置文件" not in output:
            status = "pass"
            details = "日志轮转配置存在"
        else:
            status = "info"
            details = "日志轮转配置需要检查"
        
        self.add_result("security_audit", "3.4 日志轮转配置", 
                       "ls -l /etc/logrotate.d/syslog", 
                       output, status, details)
    
    def check_intrusion_prevention(self):
        """检查入侵防范"""
        print(f"\n{Colors.BLUE}[4/8] 检查入侵防范...{Colors.END}")
        
        # 4.1 防火墙状态
        success, output, error = self.ssh.execute(
            "systemctl status firewalld --no-pager 2>/dev/null || "
            "systemctl status iptables --no-pager 2>/dev/null || "
            "echo '防火墙服务未找到'"
        )
        if success:
            if "active (running)" in output:
                status = "pass"
                details = "防火墙服务正在运行"
            else:
                status = "warning"
                details = "防火墙服务未运行"
        else:
            status = "info"
        
        self.add_result("intrusion", "4.1 防火墙状态", 
                       "systemctl status firewalld --no-pager", 
                       output, status, details)
        
        # 4.2 网络服务监听
        success, output, error = self.ssh.execute(
            "ss -tuln 2>/dev/null | grep LISTEN | head -10"
        )
        if success:
            status = "info"
            details = "需要人工检查网络服务监听情况"
        else:
            status = "info"
        
        self.add_result("intrusion", "4.2 网络服务监听", 
                       "ss -tuln | grep LISTEN", 
                       output, status, details)
        
        # 4.3 系统更新
        success, output, error = self.ssh.execute(
            "yum check-update 2>/dev/null 2>&1 | wc -l"
        )
        if success and output.isdigit():
            update_count = int(output)
            if update_count == 0:
                status = "pass"
                details = "系统已是最新状态"
            else:
                status = "warning"
                details = f"系统有 {update_count} 个可用更新"
        else:
            status = "info"
            output = "无法检查更新"
            details = "无法检查系统更新"
        
        self.add_result("intrusion", "4.3 系统更新检查", 
                       "yum check-update | wc -l", 
                       output, status, details)
        
        # 4.4 入侵检测系统
        success, output, error = self.ssh.execute(
            "ps aux 2>/dev/null | grep -E '(aide|tripwire|ossec|snort)' | grep -v grep"
        )
        if success and output:
            status = "pass"
            details = "入侵检测系统正在运行"
        else:
            status = "info"
            details = "未发现入侵检测系统"
        
        self.add_result("intrusion", "4.4 入侵检测系统", 
                       "ps aux | grep -E '(aide|tripwire|ossec|snort)'", 
                       output, status, details)
    
    def check_malware_protection(self):
        """检查恶意代码防护"""
        print(f"\n{Colors.BLUE}[5/8] 检查恶意代码防护...{Colors.END}")
        
        # 5.1 防病毒软件
        success, output, error = self.ssh.execute(
            "ps aux 2>/dev/null | grep -E '(clam|antivirus|kaspersky|norton|sophos)' | grep -v grep"
        )
        if success and output:
            status = "pass"
            details = "防病毒软件正在运行"
        else:
            status = "warning"
            details = "未发现防病毒软件运行"
        
        self.add_result("malware", "5.1 防病毒软件检查", 
                       "ps aux | grep -E '(clam|antivirus|kaspersky|norton|sophos)'", 
                       output, status, details)
        
        # 5.2 Rootkit检查工具
        success, output, error = self.ssh.execute(
            "which rkhunter chkrootkit 2>/dev/null || echo '未安装'"
        )
        if success and "未安装" not in output:
            status = "pass"
            details = "Rootkit检查工具已安装"
        else:
            status = "info"
            details = "Rootkit检查工具未安装"
        
        self.add_result("malware", "5.2 Rootkit检查工具", 
                       "which rkhunter chkrootkit", 
                       output, status, details)
    
    def check_data_integrity(self):
        """检查数据完整性"""
        print(f"\n{Colors.BLUE}[6/8] 检查数据完整性...{Colors.END}")
        
        # 6.1 文件完整性工具
        success, output, error = self.ssh.execute(
            "rpm -qa 2>/dev/null | grep -E '(aide|tripwire)'"
        )
        if success and output:
            status = "pass"
            details = "文件完整性检查工具已安装"
        else:
            status = "info"
            details = "文件完整性检查工具未安装"
        
        self.add_result("data_integrity", "6.1 文件完整性工具", 
                       "rpm -qa | grep -E '(aide|tripwire)'", 
                       output, status, details)
        
        # 6.2 系统关键文件
        success, output, error = self.ssh.execute(
            "ls -la /bin/ls /bin/ps /bin/netstat /usr/bin/who /usr/bin/w 2>/dev/null"
        )
        if success:
            status = "info"
            details = "需要人工检查系统关键文件的权限和完整性"
        else:
            status = "info"
        
        self.add_result("data_integrity", "6.2 系统关键文件检查", 
                       "ls -la /bin/ls /bin/ps /bin/netstat /usr/bin/who /usr/bin/w", 
                       output, status, details)
    
    def check_data_confidentiality(self):
        """检查数据保密性"""
        print(f"\n{Colors.BLUE}[7/8] 检查数据保密性...{Colors.END}")
        
        # 7.1 磁盘加密
        success, output, error = self.ssh.execute(
            "lsblk -f 2>/dev/null | grep crypt || echo '未发现加密分区'"
        )
        if success and "未发现加密分区" not in output:
            status = "pass"
            details = "发现磁盘加密分区"
        else:
            status = "info"
            details = "未发现磁盘加密分区"
        
        self.add_result("data_confidentiality", "7.1 磁盘加密检查", 
                       "lsblk -f | grep crypt", 
                       output, status, details)
        
        # 7.2 SSL/TLS配置
        success, output, error = self.ssh.execute(
            "openssl version 2>/dev/null && which openssl"
        )
        if success:
            status = "pass"
            details = "OpenSSL已安装"
        else:
            status = "info"
            details = "OpenSSL未安装"
        
        self.add_result("data_confidentiality", "7.2 SSL/TLS配置", 
                       "openssl version && which openssl", 
                       output, status, details)
    
    def check_residual_information(self):
        """检查剩余信息保护（包含命令历史记录配置检查）"""
        print(f"\n{Colors.BLUE}[8/8] 检查剩余信息保护...{Colors.END}")
        
        # 8.1 交换分区
        success, output, error = self.ssh.execute(
            "swapon --show 2>/dev/null && cat /proc/swaps 2>/dev/null || echo '未找到swap信息'"
        )
        if success:
            status = "info"
            details = "建议对swap分区进行加密"
        else:
            status = "info"
        
        self.add_result("residual_info", "8.1 交换分区检查", 
                       "swapon --show && cat /proc/swaps", 
                       output, status, details)
        
        # 8.2 临时文件清理
        success, output, error = self.ssh.execute(
            "systemctl status systemd-tmpfiles-clean.timer --no-pager 2>/dev/null"
        )
        if success and "active (waiting)" in output:
            status = "pass"
            details = "临时文件清理服务已启用"
        else:
            status = "info"
            details = "临时文件清理服务需要检查"
        
        self.add_result("residual_info", "8.2 临时文件清理", 
                       "systemctl status systemd-tmpfiles-clean.timer --no-pager", 
                       output, status, details)
        
        # 8.3 命令历史记录配置检查（新增）
        print(f"{Colors.CYAN}  检查命令历史记录配置...{Colors.END}")
        
        # 8.3.1 HISTSIZE和HISTFILESIZE配置
        success, output, error = self.ssh.execute(
            "echo $HISTSIZE $HISTFILESIZE && grep -E 'HISTSIZE|HISTFILESIZE' /etc/profile /etc/bashrc ~/.bashrc ~/.bash_profile 2>/dev/null | grep -v '^#'"
        )
        
        if success:
            lines = output.strip().split('\n')
            histsize = None
            histfilesize = None
            
            # 从环境变量获取
            if lines and lines[0]:
                parts = lines[0].split()
                if len(parts) >= 2:
                    try:
                        histsize = int(parts[0])
                        histfilesize = int(parts[1])
                    except:
                        pass
            
            # 从配置文件中获取
            for line in lines[1:]:
                if 'HISTSIZE=' in line:
                    try:
                        match = re.search(r'HISTSIZE\s*=\s*(\d+)', line)
                        if match:
                            histsize = int(match.group(1))
                    except:
                        pass
                elif 'HISTFILESIZE=' in line:
                    try:
                        match = re.search(r'HISTFILESIZE\s*=\s*(\d+)', line)
                        if match:
                            histfilesize = int(match.group(1))
                    except:
                        pass
            
            if histsize is not None and histfilesize is not None:
                if histsize <= 1000 and histfilesize <= 2000:
                    status = "pass"
                    details = f"历史记录大小配置合理（HISTSIZE={histsize}, HISTFILESIZE={histfilesize}）"
                else:
                    status = "warning"
                    details = f"历史记录大小可能过大（HISTSIZE={histsize}, HISTFILESIZE={histfilesize}），建议减小"
            else:
                status = "info"
                details = "历史记录大小配置不明确"
        else:
            status = "info"
            details = "无法检查历史记录配置"
        
        self.add_result("residual_info", "8.3.1 历史记录大小配置", 
                       "echo $HISTSIZE $HISTFILESIZE && grep -E 'HISTSIZE|HISTFILESIZE' /etc/profile /etc/bashrc ~/.bashrc ~/.bash_profile", 
                       output, status, details)
        
        # 8.3.2 history文件权限检查
        success, output, error = self.ssh.execute(
            "ls -la ~/.bash_history /root/.bash_history 2>/dev/null && stat -c '%a %U %G' ~/.bash_history /root/.bash_history 2>/dev/null"
        )
        
        if success:
            lines = output.strip().split('\n')
            permission_issues = []
            
            for line in lines:
                if '.bash_history' in line:
                    # 检查权限
                    if '-rw-------' in line or '-rw-r-----' in line:
                        # 权限正确
                        pass
                    else:
                        # 权限过大
                        if 'root' in line:
                            permission_issues.append("root用户history文件权限过大")
                        else:
                            permission_issues.append(f"history文件权限过大: {line.split()[0]}")
            
            if permission_issues:
                status = "fail"
                details = f"history文件权限问题: {'; '.join(permission_issues)}"
            else:
                status = "pass"
                details = "history文件权限设置合理"
        else:
            status = "info"
            details = "无法检查history文件权限"
        
        self.add_result("residual_info", "8.3.2 history文件权限", 
                       "ls -la ~/.bash_history /root/.bash_history && stat -c '%a %U %G' ~/.bash_history /root/.bash_history", 
                       output, status, details)
        
        # 8.3.3 敏感命令历史记录处理配置
        success, output, error = self.ssh.execute(
            "grep -E 'HISTCONTROL|HISTIGNORE' /etc/profile /etc/bashrc ~/.bashrc ~/.bash_profile 2>/dev/null | grep -v '^#'"
        )
        
        if success and output:
            lines = output.strip().split('\n')
            histcontrol_set = False
            histignore_set = False
            
            for line in lines:
                if 'HISTCONTROL=' in line:
                    if 'ignorespace' in line or 'ignoredups' in line or 'ignoreboth' in line:
                        histcontrol_set = True
                elif 'HISTIGNORE=' in line:
                    # 检查是否忽略敏感命令
                    sensitive_commands = ['passwd', 'su', 'sudo', 'ssh', 'exit', 'reboot', 'shutdown']
                    line_lower = line.lower()
                    if any(cmd in line_lower for cmd in sensitive_commands):
                        histignore_set = True
            
            if histcontrol_set or histignore_set:
                status = "pass"
                details = "已配置敏感命令历史记录处理"
                if histcontrol_set:
                    details += "（HISTCONTROL已设置）"
                if histignore_set:
                    details += "（HISTIGNORE包含敏感命令）"
            else:
                status = "info"
                details = "未配置敏感命令历史记录处理"
        else:
            status = "info"
            details = "未找到敏感命令历史记录处理配置"
        
        self.add_result("residual_info", "8.3.3 敏感命令历史记录处理", 
                       "grep -E 'HISTCONTROL|HISTIGNORE' /etc/profile /etc/bashrc ~/.bashrc ~/.bash_profile", 
                       output, status, details)
        
        # 8.3.4 当前history配置检查
        success, output, error = self.ssh.execute(
            "history 2>/dev/null | tail -5 && echo '总历史记录数:' && history 2>/dev/null | wc -l"
        )
        
        if success:
            lines = output.strip().split('\n')
            if len(lines) > 1:
                history_count = lines[-1]
                recent_commands = '\n'.join(lines[:-1])
                
                details = f"最近命令: {recent_commands}...，总记录数: {history_count}"
                status = "info"
            else:
                details = "无法获取history信息"
                status = "info"
        else:
            details = "无法检查当前history"
            status = "info"
        
        self.add_result("residual_info", "8.3.4 当前命令历史记录", 
                       "history | tail -5 && echo '总历史记录数:' && history | wc -l", 
                       output, status, details)
        
        # 8.3.5 命令历史记录配置总结
        success, output1, _ = self.ssh.execute("echo $HISTSIZE")
        success, output2, _ = self.ssh.execute("ls -la ~/.bash_history 2>/dev/null | head -1")
        
        summary_output = f"HISTSIZE: {output1 if output1 else '未设置'}, "
        if output2 and '.bash_history' in output2:
            summary_output += f"history文件权限: {output2.split()[0]}"
        else:
            summary_output += "history文件: 未找到或无法访问"
        
        # 综合判断
        if "pass" in [r["status"] for r in self.results["residual_info"][-4:-1]]:
            summary_status = "pass"
            summary_details = "命令历史记录配置基本合理"
        elif "fail" in [r["status"] for r in self.results["residual_info"][-4:-1]]:
            summary_status = "warning"
            summary_details = "命令历史记录配置存在安全风险"
        else:
            summary_status = "info"
            summary_details = "命令历史记录配置需要进一步检查"
        
        self.add_result("residual_info", "8.3.5 命令历史记录配置总结", 
                       "N/A (综合检查结果)", 
                       summary_output, 
                       summary_status, summary_details)
    
    def run_all_checks(self):
        """运行所有检查"""
        self.gather_system_info()
        self.check_identity()
        self.check_access_control()
        self.check_security_audit()
        self.check_intrusion_prevention()
        self.check_malware_protection()
        self.check_data_integrity()
        self.check_data_confidentiality()
        self.check_residual_information()
    
    def get_statistics(self) -> Dict:
        """获取统计信息"""
        stats = {
            "total_checks": 0,
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "infos": 0,
            "by_category": {}
        }
        
        for category, items in self.results.items():
            cat_stats = {"total": 0, "passed": 0, "failed": 0, "warnings": 0, "infos": 0}
            
            for item in items:
                stats["total_checks"] += 1
                cat_stats["total"] += 1
                
                if item["status"] == "pass":
                    stats["passed"] += 1
                    cat_stats["passed"] += 1
                elif item["status"] == "fail":
                    stats["failed"] += 1
                    cat_stats["failed"] += 1
                elif item["status"] == "warning":
                    stats["warnings"] += 1
                    cat_stats["warnings"] += 1
                elif item["status"] == "info":
                    stats["infos"] += 1
                    cat_stats["infos"] += 1
            
            stats["by_category"][category] = cat_stats
        
        return stats
    
    def generate_html_report(self, output_file: str = None):
        """生成HTML报告（修复文件名安全）"""
        if not TEMPLATE_AVAILABLE:
            print(f"{Colors.RED}错误: jinja2库未安装，无法生成HTML报告{Colors.END}")
            return False
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # 获取安全的主机名
            hostname = self.system_info.get('hostname', 'unknown')
            # 再次清理，确保安全
            safe_hostname = re.sub(r'[^a-zA-Z0-9._-]', '_', hostname)
            if not safe_hostname or safe_hostname.strip('_') == '':
                safe_hostname = 'unknown'
            output_file = f"security_audit_{safe_hostname}_{timestamp}.html"
        
        # 获取统计信息
        stats = self.get_statistics()
        
        # 类别名称映射
        category_names = {
            "identity": "身份鉴别",
            "access_control": "访问控制",
            "security_audit": "安全审计",
            "intrusion": "入侵防范",
            "malware": "恶意代码防护",
            "data_integrity": "数据完整性",
            "data_confidentiality": "数据保密性",
            "residual_info": "剩余信息保护"
        }
        
        # 状态图标
        status_icons = {
            "pass": "✅",
            "fail": "❌",
            "warning": "⚠️",
            "info": "ℹ️"
        }
        
        # 状态颜色
        status_colors = {
            "pass": "success",
            "fail": "danger",
            "warning": "warning",
            "info": "info"
        }
        
        # HTML模板
        html_template = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>麒麟操作系统等级保护安全配置核查报告</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {
            font-family: 'Microsoft YaHei', 'Segoe UI', Arial, sans-serif;
            background-color: #f8f9fa;
            padding-bottom: 50px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 0;
            margin-bottom: 30px;
            border-radius: 0 0 20px 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            margin-bottom: 20px;
            transition: transform 0.3s;
        }
        .card:hover {
            transform: translateY(-5px);
        }
        .card-header {
            background-color: white;
            border-bottom: 2px solid #f0f0f0;
            font-weight: bold;
            padding: 15px 20px;
        }
        .command {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            overflow-x: auto;
        }
        .output {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
        .status-pass { color: #28a745; }
        .status-fail { color: #dc3545; }
        .status-warning { color: #ffc107; }
        .status-info { color: #17a2b8; }
        .progress {
            height: 25px;
            border-radius: 12px;
        }
        .stat-card {
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            color: white;
            margin-bottom: 20px;
        }
        .stat-total { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .stat-pass { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); }
        .stat-fail { background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%); }
        .stat-warning { background: linear-gradient(135deg, #ffc107 0%, #ff922b 100%); }
        .summary-table th {
            background-color: #f8f9fa;
        }
        .collapse-btn {
            text-decoration: none;
            color: #495057;
        }
        .collapse-btn:hover {
            color: #007bff;
        }
        .footer {
            margin-top: 50px;
            padding: 20px;
            background-color: #f8f9fa;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #6c757d;
        }
        .risk-level {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: bold;
        }
        .risk-low { background-color: #d4edda; color: #155724; }
        .risk-medium { background-color: #fff3cd; color: #856404; }
        .risk-high { background-color: #f8d7da; color: #721c24; }
        .accordion-button:not(.collapsed) {
            background-color: rgba(0,123,255,0.1);
            color: #0c63e4;
        }
        .new-feature {
            border-left: 4px solid #ff6b6b;
        }
        .feature-tag {
            background-color: #ff6b6b;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            margin-left: 8px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1 class="display-4"><i class="fas fa-shield-alt"></i> 麒麟操作系统安全配置核查报告</h1>
            <p class="lead">等级保护测评 - 完整版（包含新增检查项）</p>
            <div class="row mt-4">
                <div class="col-md-3">
                    <p><i class="fas fa-server"></i> <strong>目标主机:</strong> {{ system_info.hostname }}</p>
                </div>
                <div class="col-md-3">
                    <p><i class="fas fa-desktop"></i> <strong>操作系统:</strong> {{ system_info.os }}</p>
                </div>
                <div class="col-md-3">
                    <p><i class="fas fa-code-branch"></i> <strong>内核版本:</strong> {{ system_info.kernel }}</p>
                </div>
                <div class="col-md-3">
                    <p><i class="fas fa-network-wired"></i> <strong>IP地址:</strong> {{ system_info.ip }}</p>
                </div>
            </div>
            <div class="row">
                <div class="col-md-6">
                    <p><i class="fas fa-calendar-alt"></i> <strong>核查时间:</strong> {{ audit_time }}</p>
                </div>
                <div class="col-md-6">
                    <p><i class="fas fa-user"></i> <strong>SSH用户:</strong> {{ ssh_user }}</p>
                </div>
            </div>
            <div class="alert alert-light mt-3" style="opacity: 0.9;">
                <i class="fas fa-plus-circle"></i> <strong>新增检查项:</strong> 
                登录超时配置 | 多余账户检查 | 命令历史记录配置
            </div>
        </div>
    </div>

    <div class="container">
        <!-- 统计概览 -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-card stat-total">
                    <h3>{{ stats.total_checks }}</h3>
                    <p>总检查项</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card stat-pass">
                    <h3>{{ stats.passed }}</h3>
                    <p>通过项</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card stat-fail">
                    <h3>{{ stats.failed }}</h3>
                    <p>失败项</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card stat-warning">
                    <h3>{{ stats.warnings }}</h3>
                    <p>警告项</p>
                </div>
            </div>
        </div>

        <!-- 通过率 -->
        <div class="card mb-4">
            <div class="card-header">
                <i class="fas fa-chart-line"></i> 检查结果概览
            </div>
            <div class="card-body">
                {% set pass_rate = (stats.passed / stats.total_checks * 100) if stats.total_checks > 0 else 0 %}
                <h5>总体通过率: {{ "%.1f"|format(pass_rate) }}%</h5>
                <div class="progress mb-4">
                    <div class="progress-bar bg-success" role="progressbar" 
                         style="width: {{ pass_rate }}%">{{ "%.1f"|format(pass_rate) }}%</div>
                </div>
                
                <div class="table-responsive">
                    <table class="table table-bordered summary-table">
                        <thead>
                            <tr>
                                <th>测评项</th>
                                <th>检查项数</th>
                                <th>通过数</th>
                                <th>未通过数</th>
                                <th>通过率</th>
                                <th>风险等级</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for category_id, category_name in category_names.items() %}
                                {% set cat_stats = stats.by_category[category_id] %}
                                {% set cat_pass_rate = (cat_stats.passed / cat_stats.total * 100) if cat_stats.total > 0 else 0 %}
                                {% set risk_level = "low" if cat_pass_rate >= 80 else "medium" if cat_pass_rate >= 60 else "high" %}
                                <tr>
                                    <td>
                                        <strong>{{ category_name }}</strong>
                                        {% if category_id == "identity" %}
                                            <span class="feature-tag">新增超时检查</span>
                                        {% elif category_id == "access_control" %}
                                            <span class="feature-tag">新增账户检查</span>
                                        {% elif category_id == "residual_info" %}
                                            <span class="feature-tag">新增历史记录</span>
                                        {% endif %}
                                    </td>
                                    <td>{{ cat_stats.total }}</td>
                                    <td class="status-pass">{{ cat_stats.passed }}</td>
                                    <td class="status-fail">{{ cat_stats.failed + cat_stats.warnings }}</td>
                                    <td>{{ "%.1f"|format(cat_pass_rate) }}%</td>
                                    <td>
                                        <span class="risk-level risk-{{ risk_level }}">
                                            {% if risk_level == "low" %}低风险
                                            {% elif risk_level == "medium" %}中风险
                                            {% else %}高风险
                                            {% endif %}
                                        </span>
                                    </td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- 详细检查结果 -->
        <div class="accordion" id="resultsAccordion">
            {% for category_id, category_name in category_names.items() %}
                <div class="card mb-2 {% if category_id in ['identity', 'access_control', 'residual_info'] %}new-feature{% endif %}">
                    <div class="card-header" id="heading{{ loop.index }}">
                        <h2 class="mb-0">
                            <button class="btn btn-link btn-block text-left collapse-btn" type="button" 
                                    data-bs-toggle="collapse" data-bs-target="#collapse{{ loop.index }}" 
                                    aria-expanded="false" aria-controls="collapse{{ loop.index }}">
                                <i class="fas fa-chevron-down"></i>
                                {{ category_name }} ({{ results[category_id]|length }} 项)
                                {% if category_id == "identity" %}
                                    <span class="badge bg-danger">新增超时检查</span>
                                {% elif category_id == "access_control" %}
                                    <span class="badge bg-warning">新增账户检查</span>
                                {% elif category_id == "residual_info" %}
                                    <span class="badge bg-info">新增历史记录</span>
                                {% endif %}
                            </button>
                        </h2>
                    </div>
                    
                    <div id="collapse{{ loop.index }}" class="collapse" 
                         aria-labelledby="heading{{ loop.index }}" data-bs-parent="#resultsAccordion">
                        <div class="card-body">
                            {% for item in results[category_id] %}
                                <div class="card mb-3 border-{{ status_colors[item.status] }}">
                                    <div class="card-body">
                                        <h5 class="card-title">
                                            {{ status_icons[item.status] }} {{ item.title }}
                                            <span class="badge bg-{{ status_colors[item.status] }} float-end">
                                                {{ item.status|upper }}
                                            </span>
                                        </h5>
                                        <p class="card-text">{{ item.details }}</p>
                                        
                                        <div class="mb-2">
                                            <small class="text-muted">执行命令:</small>
                                            <div class="command">{{ item.command }}</div>
                                        </div>
                                        
                                        {% if item.output %}
                                            <div class="mb-2">
                                                <small class="text-muted">输出结果:</small>
                                                <div class="output">{{ item.output }}</div>
                                            </div>
                                        {% endif %}
                                        
                                        <small class="text-muted">
                                            <i class="fas fa-clock"></i> 检查时间: {{ item.timestamp }}
                                        </small>
                                    </div>
                                </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
            {% endfor %}
        </div>

        <!-- 风险和建议 -->
        <div class="card mt-4 border-warning">
            <div class="card-header bg-warning text-white">
                <i class="fas fa-exclamation-triangle"></i> 安全建议
            </div>
            <div class="card-body">
                <h5>风险概述</h5>
                <p>本次检查发现 <strong class="text-danger">{{ stats.failed }} 个高危问题</strong> 和 
                   <strong class="text-warning">{{ stats.warnings }} 个中危问题</strong>。</p>
                
                {% if stats.failed > 0 %}
                    <div class="alert alert-danger">
                        <i class="fas fa-fire"></i> <strong>发现高危安全问题，建议立即处理！</strong>
                    </div>
                {% elif stats.warnings > 0 %}
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-circle"></i> <strong>发现中危安全问题，建议尽快处理！</strong>
                    </div>
                {% else %}
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i> <strong>系统安全配置良好，建议继续保持！</strong>
                    </div>
                {% endif %}
                
                <h5 class="mt-4">新增检查项建议</h5>
                <div class="row">
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header bg-info text-white">
                                <i class="fas fa-clock"></i> 登录超时配置
                            </div>
                            <div class="card-body">
                                <ul class="mb-0">
                                    <li>配置SSH ClientAliveInterval（建议300秒）</li>
                                    <li>设置Shell TMOUT环境变量</li>
                                    <li>配置sudo timestamp_timeout</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <i class="fas fa-users"></i> 多余账户管理
                            </div>
                            <div class="card-body">
                                <ul class="mb-0">
                                    <li>删除未使用的系统账户</li>
                                    <li>确保只有root的UID为0</li>
                                    <li>定期清理过期账户</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header bg-success text-white">
                                <i class="fas fa-history"></i> 命令历史记录
                            </div>
                            <div class="card-body">
                                <ul class="mb-0">
                                    <li>限制history记录数量</li>
                                    <li>设置history文件权限</li>
                                    <li>配置敏感命令忽略</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
                
                <h5 class="mt-4">通用建议措施</h5>
                <ul>
                    <li>定期更新系统和安全补丁</li>
                    <li>加强密码策略和账户管理</li>
                    <li>配置并启用安全审计功能</li>
                    <li>安装并更新防病毒软件</li>
                    <li>定期进行安全配置核查</li>
                    <li>重要数据实施加密保护</li>
                </ul>
            </div>
        </div>
    </div>

    <div class="footer">
        <div class="container">
            <p>报告生成时间: {{ audit_time }}</p>
            <p>生成主机: {{ local_hostname }}</p>
            <p class="text-muted">
                <small>
                    注：本报告仅供参考，实际测评请以等级保护正式测评结果为准<br>
                    核查脚本版本: v2.1 完整版（包含登录超时、多余账户、命令历史记录检查）
                </small>
            </p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 自动展开第一个有问题的分类
        document.addEventListener('DOMContentLoaded', function() {
            // 自动展开包含新增检查项的分类
            const newFeatureCategories = ['identity', 'access_control', 'residual_info'];
            newFeatureCategories.forEach((categoryId, index) => {
                const collapseId = `collapse${index + 1}`;
                const collapseElement = document.getElementById(collapseId);
                if (collapseElement) {
                    new bootstrap.Collapse(collapseElement, { toggle: true });
                }
            });
        });
    </script>
</body>
</html>
        """
        
        # 准备模板数据
        template_data = {
            "system_info": self.system_info,
            "results": self.results,
            "stats": stats,
            "category_names": category_names,
            "status_icons": status_icons,
            "status_colors": status_colors,
            "audit_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ssh_user": self.ssh.username if self.ssh else "未知",
            "local_hostname": socket.gethostname()
        }
        
        try:
            # 使用jinja2渲染模板
            env = jinja2.Environment()
            template = env.from_string(html_template)
            html_content = template.render(**template_data)
            
            # 写入文件
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Colors.GREEN}✓ HTML报告已生成: {output_file}{Colors.END}")
            return output_file
            
        except Exception as e:
            print(f"{Colors.RED}生成HTML报告失败: {e}{Colors.END}")
            return None

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='麒麟操作系统等级保护安全配置核查脚本（完整版）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
新增检查项：
  1. 登录连接超时自动退出功能检查（SSH/Shell/sudo超时）
  2. 多余账户检查（UID为0账户、系统账户、未使用账户）
  3. 命令历史记录配置检查（HISTSIZE、权限、敏感命令）

示例:
  %(prog)s -H 192.168.1.100 -u root                     # 使用交互式密码
  %(prog)s -H server.example.com -u admin -k id_rsa    # 使用SSH密钥
  %(prog)s -H 192.168.1.100 -u root -p 2222 -o report.html  # 指定端口和输出文件
  
安全提示:
  - 不建议在命令行中直接使用-P参数，密码会出现在进程列表中
  - 推荐使用交互式密码输入或SSH密钥认证
        '''
    )
    
    parser.add_argument('-H', '--host', required=True, help='目标主机IP地址或域名')
    parser.add_argument('-u', '--user', required=True, help='SSH用户名')
    parser.add_argument('-p', '--port', type=int, default=22, help='SSH端口 (默认: 22)')
    parser.add_argument('-k', '--key', help='SSH私钥文件路径')
    parser.add_argument('-P', '--password', help='SSH密码（不推荐）')
    parser.add_argument('-o', '--output', help='输出报告文件路径')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='SSH超时时间 (默认: 30秒)')
    parser.add_argument('--no-html', action='store_true', help='不生成HTML报告')
    
    args = parser.parse_args()
    
    # 检查必要的库
    if not SSH_AVAILABLE:
        print(f"{Colors.RED}错误: paramiko库未安装，无法进行SSH连接{Colors.END}")
        print("请先安装: pip install paramiko")
        sys.exit(1)
    
    # 如果未指定密码且未指定密钥，则提示输入密码
    password = args.password
    if not password and not args.key:
        print(f"{Colors.YELLOW}请输入SSH密码（输入不会显示）:{Colors.END} ", end='', flush=True)
        password = getpass.getpass()
        if not password:
            print(f"{Colors.RED}错误: 密码不能为空{Colors.END}")
            sys.exit(1)
    
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.CYAN}麒麟操作系统等级保护安全配置核查脚本（完整版）{Colors.END}")
    print(f"{Colors.CYAN}版本: 2.1 - 包含所有新增检查项{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
    
    # 创建SSH客户端
    ssh = SSHClient(
        host=args.host,
        port=args.port,
        username=args.user,
        password=password,
        key_file=args.key
    )
    
    # 连接SSH
    if not ssh.connect():
        print(f"{Colors.RED}无法连接到SSH服务器，请检查连接参数{Colors.END}")
        sys.exit(1)
    
    try:
        # 创建安全审计器
        auditor = SecurityAuditor(ssh)
        
        # 运行所有检查
        print(f"\n{Colors.GREEN}开始远程安全配置核查...{Colors.END}")
        print(f"{Colors.CYAN}本次检查包含新增项目：登录超时、多余账户、命令历史记录{Colors.END}")
        auditor.run_all_checks()
        
        # 显示统计信息
        stats = auditor.get_statistics()
        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.CYAN}核查完成！统计信息:{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.WHITE}总检查项: {stats['total_checks']}{Colors.END}")
        print(f"{Colors.GREEN}通过项: {stats['passed']}{Colors.END}")
        print(f"{Colors.RED}失败项: {stats['failed']}{Colors.END}")
        print(f"{Colors.YELLOW}警告项: {stats['warnings']}{Colors.END}")
        print(f"{Colors.BLUE}信息项: {stats['infos']}{Colors.END}")
        
        if stats['total_checks'] > 0:
            pass_rate = stats['passed'] / stats['total_checks'] * 100
            print(f"{Colors.CYAN}通过率: {pass_rate:.1f}%{Colors.END}")
            
            # 显示新增检查项统计
            new_checks = 0
            for category in ['identity', 'access_control', 'residual_info']:
                if category in stats['by_category']:
                    new_checks += stats['by_category'][category]['total']
            
            print(f"{Colors.PURPLE}新增检查项: {new_checks} 项{Colors.END}")
            
            if stats['failed'] > 0:
                print(f"{Colors.RED}⚠ 发现高危安全问题，建议立即处理！{Colors.END}")
            elif stats['warnings'] > 0:
                print(f"{Colors.YELLOW}⚠ 发现中危安全问题，建议尽快处理！{Colors.END}")
            else:
                print(f"{Colors.GREEN}✓ 系统安全配置良好{Colors.END}")
        
        # 生成HTML报告
        if not args.no_html:
            report_file = auditor.generate_html_report(args.output)
            if report_file:
                print(f"\n{Colors.GREEN}报告已保存至: {os.path.abspath(report_file)}{Colors.END}")
                
                # 尝试自动打开报告
                try:
                    if sys.platform == 'darwin':  # macOS
                        subprocess.run(['open', report_file], check=False)
                    elif sys.platform == 'win32':  # Windows
                        os.startfile(report_file)
                    else:  # Linux
                        subprocess.run(['xdg-open', report_file], check=False)
                except:
                    pass  # 忽略打开失败
        
        print(f"\n{Colors.CYAN}核查完成！感谢使用完整版核查工具。{Colors.END}")
        
    finally:
        # 关闭SSH连接
        ssh.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}用户中断，退出程序{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}程序执行出错: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)