"""配置类"""

import os
import json
import logging

logger = logging.getLogger(__name__)

DEFAULT_MAIL = "[necessary]your_email@qq.com"
DEFAULT_AUTH_CODE = "[necessary]your_authorization_code"

class Config():
    '''黑名单管理系统配置'''
    BLACKLIST_CONFIG_PATH = './blacklist.json' # 黑名单配置路径（现在仅储存授权码）
    def __init__(self):
        if not os.path.exists(self.BLACKLIST_CONFIG_PATH):
            self.config = {}
        else:
            with open(self.BLACKLIST_CONFIG_PATH, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        self.update_config(self.config)

    def interp_b(self, inp):
        '''将前端提交表单中的bool字段翻译成python的bool类型'''
        if isinstance(inp, str):
            return inp.lower() in ['true', 'True', '1', 'yes']
        elif isinstance(inp, int):
            return inp == 1
        else:
            return bool(inp)

    def update_config(self, update_config: dict):
        '''将前端提交的表单增量更新到配置文件'''
        cur = self.config.copy()
        cur.update(update_config) # update_config是增量的，要先拷贝原配置再update
        self.blacklist_xlsx_path = cur.get('blacklist_xlsx_path',
                                            './blacklist.xlsx') # excel导入（只读）无效时跳过
        self.blacklist_db_path = cur.get('blacklist_db_path', './blacklist.db') # 黑名单数据库路径（读&写）
        self.blacklist_assets = cur.get('blacklist_assets', './assets/black_list.bin') # 静态导出路径
        self.smtp_server = cur.get('smtp_server', 'smtp.qq.com') # SMTP服务器地址
        self.smtp_port = cur.get('smtp_port', 587) # SMTP服务器端口
        self.smtp_email = cur.get('smtp_email', DEFAULT_MAIL) # SMTP服务器用户名
        self.smtp_auth_code = cur.get('smtp_auth_code', DEFAULT_AUTH_CODE) # SMTP服务器密码
        self.host = cur.get('host', '127.0.0.1') # 服务器监听地址
        self.port = cur.get('port', 8870) # 服务器监听端口

        # 以下是调试设置，已经默认配置为生产环境设置
        self.LOGGING_LEVEL = cur.get('LOGGING_LEVEL', 'INFO') # 日志等级
        self.IS_HTTPS = self.interp_b(cur.get('IS_HTTPS', True))  # 强烈建议仅本地调试时设置IS_HTTPS=False
        self.DEBUG_DO_NOT_SEND_EMAIL = self.interp_b(cur.get('DEBUG_DO_NOT_SEND_EMAIL',
                                                             False)) # 验证码发控制台
        self.DEBUG_AVATAR_QQ_URL = self.interp_b(cur.get('DEBUG_AVATAR_QQ_URL',
                                                         True)) # 调试模式下不使用QQ头像
        new_config = {
            'blacklist_xlsx_path': self.blacklist_xlsx_path,
            'blacklist_db_path': self.blacklist_db_path,
            'blacklist_assets': self.blacklist_assets,
           'smtp_server': self.smtp_server,
           'smtp_port': self.smtp_port,
           'smtp_email': self.smtp_email,
           'smtp_auth_code': self.smtp_auth_code,
            'host': self.host,
            'port': self.port,
            'LOGGING_LEVEL': self.LOGGING_LEVEL,
            'IS_HTTPS': self.IS_HTTPS,
            'DEBUG_DO_NOT_SEND_EMAIL': self.DEBUG_DO_NOT_SEND_EMAIL,
            'DEBUG_AVATAR_QQ_URL': self.DEBUG_AVATAR_QQ_URL,
        }
        if str(new_config) != str(self.config):
            self.config = new_config
            try:
                with open(self.BLACKLIST_CONFIG_PATH, 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, ensure_ascii=False, indent=4)
                    print("黑名单配置已更新")
            except json.JSONDecodeError as e:
                logger.error("解析配置文件失败: %s", e)
            except (OSError, TypeError) as e:
                logger.error("更新配置文件发生错误: %s", e)
