from email.message import EmailMessage
import random
import smtplib
import re
import os
import sqlite3
import json
import datetime
import bcrypt
import openpyxl
import logging
import zipfile
from queue import Queue

NO_ENCODE = False # 是否不进行编码（仅用于测试）

def encoder(text: str):
    if NO_ENCODE:
        return bytearray(text.encode())
    # 转化成bytearray类型
    input = bytearray(text.encode())
    
    for i in range(len(input)):
        # 将byte的后5位取反
        input[i] = input[i] ^ 0b00011111
        # ...
    return input

def decoder(text: bytearray):
    if NO_ENCODE:
        return bytearray(text).decode()
    input = bytearray(text)
    # 转化成bytearray类型
    for i in range(len(input)):
        # 将byte的后5位取反
        input[i] = input[i] ^ 0b00011111
    
    return input.decode()


class static_export_class:
    black_list_path = './blacklist.xlsx' # 待导入的黑名单excel文件路径（仅输入不会修改）
    black_list_db_path = './blacklist.db' # 黑名单数据库路径（读&写）
    black_list_assets = '../BCZ-Notice-Examiner/assets/black_list.bin' # 黑名单数据路径（仅导出）
    black_list_string_assets = '../BCZ-Notice-Examiner/assets/black_list_string.bin' # 黑名单字符串数据路径（仅导出）
    black_list_config = './blacklist.json' # 黑名单配置路径（现在仅储存授权码）
    USER_RESEND_TIME = 60 # 同一用户连续两次发送验证码的最短间隔时间
    SERVER_RESEND_TIME = 30 # 服务器连续两次发送验证码的最短间隔时间
    EXPIRE_TIME = 600 # 验证码有效期（秒）
    MAX_VERIFY_FAIL_COUNT = 5 # 最大验证码错误次数
    
    EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")
    
    def configure_database(self, conn: sqlite3.Connection):
        cursor = conn.cursor()
        cursor.execute("PRAGMA cache_size = -65536;") # 64MB
        cursor.execute("PRAGMA temp_store = MEMORY;")
        cursor.execute("PRAGMA foreign_keys = OFF;")
        cursor.execute("PRAGMA journal_mode = MEMORY;")
        cursor.execute("PRAGMA locking_mode = EXCLUSIVE;")
        cursor.close()
        
    def detach(dict: dict) -> str: 
        '''将dict转换为key\nvalue形式的字符串'''
        result = ""
        for key, value in dict.items():
            result += f"{key}\n{value}\n"
        return result
    
    def unfold(list: list) -> str:
        '''将list转换\n形式的字符串'''
        return '\n'.join(list)

    def flatten(str: str) -> str:
        return str.replace(' ','').replace('[]','').replace('.0','')
    
    def hash_string(self, string) -> int:
        '''将string用一个顺序id表示（返回），以将储存数据中的string和数字分离达到更好的压缩效果。可以hash嵌套的list。'''
        if isinstance(string, list):
            hash_list = []
            for str_ in string:
                hash_list.append(self.hash_string(str_))
            result_str = str(hash_list)
            return -self.hash_string(result_str.replace(' ','')) # 用负数表示需要嵌套解压
        if string is None:
            string = '无'
        string = string.replace('\n', '<br>')
        if string not in self.hash_dict:
            self.hash_dict[string] = self.hash_index
            self.hash_index += 1
            return self.hash_index - 1
        else:
            return self.hash_dict[string]
        
    def recover_string(self, hash_id) -> str:
        '''将hash_id恢复为原来的字符串。可以恢复嵌套的list。'''
        if hash_id < 0:
            hash_list = json.loads(self.hash_dict[-hash_id])
            string_list = []
            for hash_id_ in hash_list:
                string_list.append(self.recover_string(hash_id_))
            return string_list
        else:
            return self.hash_dict[hash_id]

    def read_user_info(self):
        '''从数据库中读取用户信息'''
        self.logger.info("正在读取 用户信息")
        conn = sqlite3.connect(static_export_class.black_list_db_path, detect_types=0, uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT qq_id, unique_id, type, nickname, password FROM user_info")
        user_list = cursor.fetchall()
        self.user_dict = {}
        self.user_name_to_id = {}
        for row in user_list:
            self.user_dict[row[0]] = row
            self.user_name_to_id[row[3]] = row[0]
        cursor.close()
        conn.close()
        self.logger.info("用户信息读取完成")

    def check_exist(self, uid, create_time):
        '''检查(uid, create_time)是否已经存在于黑名单，也就是唯一记录'''
        id = (uid, create_time)
        if uid not in self.blacklist_date:
            self.blacklist_date[uid] = [id]
            return False
        if id in self.blacklist_date[uid]:
            return True
        self.blacklist_date[uid].append(id)
        return False

    def read_blacklist_db(self):
        '''从数据库中读取黑名单（合并到内存）'''
        self.logger.info("正在读取 黑名单数据库")
        conn = sqlite3.connect(static_export_class.black_list_db_path, detect_types=0, uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT hash_id, string FROM string_hash")
        hash_list = cursor.fetchall()
        self.hash_dict = {datetime.datetime.now().strftime('更新于%Y-%m-%d,%H:%M:%S'): 0}
        self.hash_index = 1
        for hash_id, string in hash_list:
            self.hash_dict[string] = hash_id
        cursor.execute("SELECT uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time FROM blacklist")
        blacklist_list = cursor.fetchall()
        for row in blacklist_list:
            if self.check_exist(row[0], row[1]):
                continue
            if row[6] is None:
                row[6] = self.user_name_to_id.get(row[5], None)
            if row[0] not in self.blacklist:
                self.blacklist[row[0]] = []
            self.blacklist[row[0]].append(row)
        cursor.close()
        conn.close()
    
    def read_blacklist_xlsx(self):
        '''从xlsx文件中读取黑名单（合并到内存）'''
        self.logger.info("正在读取 黑名单 excel 文件")
        if not os.path.exists(static_export_class.black_list_path):
            return []
        wb = openpyxl.load_workbook(static_export_class.black_list_path)
        ws = wb.active
        for row in ws.iter_rows(min_row=2):
            uid = row[1].value
            if uid is None:
                continue # 跳过空行 
            try:
                uid = int(uid)
            except:
                print(f"{uid} 不是数字，对应昵称为 {row[0].value}，跳过")
                continue
            if row[2].value is None:
                print(f"{uid} 未填写退班时间，跳过")
                continue
            nickname = self.hash_string(row[0].value)
            create_time = date = int(row[2].value.timestamp())
            recorder = self.hash_string(row[4].value)
            recorder_qq_id = self.user_name_to_id.get(row[4].value, None)
            
            if self.check_exist(uid, date):
                continue

            reason = None
            if row[3].value is not None:
                reason_list = row[3].value.split(',')
                reason = self.hash_string(reason_list)
            else:
                reason = self.hash_string([])
                
            
            remark = self.hash_string(row[5].value)

            if row[6].value is None:
                continue
            last_edit_time = row[6].value.timestamp()
            try:
                last_editor = self.hash_string(row[7].value)
                # if not recorder_qq_id:
                #     recorder_qq_id = self.user_name_to_id.get(row[7].value, None)
            except:
                last_editor = self.hash_string('无')
            try:
                first_editor = self.hash_string(row[8].value)
                # if not recorder_qq_id:
                #     recorder_qq_id = self.user_name_to_id.get(row[8].value, None)
            except:
                first_editor = self.hash_string('无')

            
            if uid not in self.blacklist:
                self.blacklist[uid] = []
            self.blacklist[uid].append((uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time))

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.hash_index = 0
        self.hash_dict = {}
        self.blacklist = {}
        self.blacklist_date = {}
        self.last_email_sent_time = 0
        self.email_cache = {}  # 邮箱验证码缓存
        self.result = []
        self.result_keyword = ""

        # 检查文件是否存在
        if not os.path.exists(static_export_class.black_list_path):
            self.logger.error("黑名单excel文件不存在，请检查路径")
            self.config = {
                "SMTP_SERVER": "smtp.qq.com",
                "SMTP_PORT": 587,
                "email": "[necessary]your_email@qq.com",
                "auth_code": "[necessary]your_authorization_code"
            }
        else:
            with open(static_export_class.black_list_config, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        self.SMTP_SERVER = self.config.get("SMTP_SERVER", "smtp.qq.com") # 用于发送验证码邮件
        self.SMTP_PORT = self.config.get("SMTP_PORT", 587) # 用于发送验证码邮件
        self.email = self.config.get("email", None) # 用于发送验证码邮件
        self.auth_code = self.config.get("auth_code", None) # 验证码发送邮箱的授权码
        self.earlist_email = None # 最临近过期的验证码邮箱
        self.earlist_sent_time = 0 # 最临近过期的验证码发送时间
        self.email_cache = {}
        self.verify_fail_count = {} # 记录某个邮箱验证码发送失败次数，防止暴力破解
        self.email_queue = Queue()
        # 初始化数据库
        self.logger.info("正在初始化 黑名单数据库")
        conn = sqlite3.connect(static_export_class.black_list_db_path, detect_types=0, uri=True)
        self.configure_database(conn)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS blacklist (
            uid INTEGER NOT NULL, -- 被拉黑用户的unique_id(同一人被多次拉黑的情况较少，不hash)
            create_time INTEGER NOT NULL, -- timestamp
            nickname INTEGER NOT NULL,
            date INTEGER NOT NULL,
            reason INTEGER NOT NULL,
            recorder INTEGER NOT NULL,
            recorder_qq_id INTEGER, -- 也是hash值
            remark INTEGER NOT NULL,
            last_edit_time INTEGER NOT NULL,
         PRIMARY KEY (uid, create_time))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS string_hash (
            hash_id INTEGER PRIMARY KEY,
            string TEXT NOT NULL
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_info (
            qq_id INTEGER PRIMARY KEY, -- 非hash，每个qq号只能对应一个账号，只填大号uid就好了
            unique_id INTEGER, -- 非hash
            type INTEGER, -- 0为管理员，1为普通用户，2为王者班长
            nickname TEXT, -- 非hash
            password TEXT -- 管理员可以添加password为空的用户以便后续注册后直接获得相应身份组
        )''')
        conn.commit()
        cursor.close()
        conn.close()
        self.__ready = False
        self.logger.info("黑名单数据库初始化完成")
    
    def expire(self, timestamp):
        '''删除过期的验证码(生产环境用Redis)'''
        if self.email_queue.empty():
            return
        while timestamp - self.earlist_sent_time > self.EXPIRE_TIME:
            if self.email_cache.get(self.earlist_email, {'code':0, 'timestamp':1})['timestamp'] == self.earlist_sent_time: # 用户没有重新发送验证码
                self.email_cache.pop(self.earlist_email) # 先删除已经过期的验证码
            if self.email_queue.empty():
                break
            self.earlist_email, self.earlist_sent_time = self.email_queue.get() # 获取下一个即将过期的验证码

    def reg(self, email, verify_code):
        '''记录验证码(防暴力措施不在这里)'''
        timestamp = datetime.datetime.now()
        self.expire(timestamp)
        # 直接覆盖旧的验证码，因为在删除过期时会自动验证
        self.email_cache[email] = {
            "code": verify_code,
            "timestamp": timestamp
        }
        self.email_queue.put((email, timestamp))
    
    def check(self, email, verify_code):
        '''验证验证码(防暴力措施不在这里)0为失败，1为请重新发送，2为成功'''
        timestamp = datetime.datetime.now()
        self.expire(timestamp)
        if email not in self.email_cache:
            return 0
        if self.email_cache[email]['code'] != verify_code:
            self.verify_fail_count[email] = self.verify_fail_count.get(email, 0) + 1
            if self.verify_fail_count[email] >= self.MAX_VERIFY_FAIL_COUNT:
                self.email_cache.pop(email) # 超过最大次数，删除验证码
                return 1
            return 0
        # 删除验证码
        self.email_cache.pop(email)
        return 2

    def verify_password(self, password):
        '''检查密码是否符合要求(密码长度至少8位，包含数字和字母)'''
        if len(password) < 8:
            return False
        if not re.search(r"[0-9]+", password):
            return False
        if not re.search(r"[a-zA-Z]+", password):
            return False
        return True
    
    def prepare(self):
        if not self.__ready:
            self.logger.info("正在读取 黑名单数据")
            self.read_user_info() # 先读取用户信息以便修复旧数据
            self.read_blacklist_db()
            self.read_blacklist_xlsx()
            self.__ready = True
            self.logger.info("黑名单数据读取完成")
    
    def export_black_list_to_db(self):
        '''导出黑名单到数据库'''
        self.prepare()
        self.logger.info("正在保存黑名单到数据库")
        conn = sqlite3.connect(static_export_class.black_list_db_path, detect_types=0, uri=True)
        self.configure_database(conn)
        cursor = conn.cursor()
        for uid, blacklist_list in self.blacklist.items():
            cursor.executemany("INSERT INTO blacklist (uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time) VALUES (?,?,?,?,?,?,?,?,?)", blacklist_list)
        for string, hash_id in self.hash_dict.items():
            cursor.execute("INSERT INTO string_hash (hash_id, string) VALUES (?,?)", (hash_id, string))

        conn.commit()
        cursor.close()
        conn.close()
        self.logger.info("黑名单已经保存到数据库")

    def export_black_list_to_bin(self):
        '''导出黑名单到静态json和bin文件'''
        self.prepare()
        self.logger.info("正在写入 黑名单 json 文件")
        with open(static_export_class.black_list_assets, 'wb') as f:
            f.write(encoder(static_export_class.flatten(static_export_class.detach(self.blacklist))))
        with zipfile.ZipFile(f"{static_export_class.black_list_assets}.zip", 'w', zipfile.ZIP_DEFLATED) as f:
            f.write(static_export_class.black_list_assets, arcname=static_export_class.black_list_assets)
        # 写入bin文件
        self.logger.info("正在写入 黑名单 bin 文件，共" + str(len(self.hash_dict)) + "条数据")
        with open(static_export_class.black_list_string_assets, 'wb') as f:
            f.write(encoder(static_export_class.flatten(static_export_class.unfold(self.hash_dict.keys()))))
        with zipfile.ZipFile(f"{static_export_class.black_list_string_assets}.zip", 'w', zipfile.ZIP_DEFLATED) as f:
            f.write(static_export_class.black_list_string_assets, arcname=static_export_class.black_list_string_assets)
        self.hash_dict = {}
        self.logger.info("黑名单导出完成")
    
    def send_verify_code(self, recv_email):
        """发送验证码邮件接口"""
        # 验证邮箱格式
        if not re.fullmatch(static_export_class.EMAIL_REGEX, recv_email):
            return 400, "无效的邮箱格式", None
        
        # 检查发送频率 (60秒内只能发送一次)
        if recv_email in self.email_cache:
            last_sent_time = self.email_cache[recv_email]['timestamp']
            last_time = datetime.datetime.now() - last_sent_time
            if last_time < self.USER_RESEND_TIME:
                return 429, f"请等待{self.USER_RESEND_TIME - last_time}秒后再试", None
        
        # 检查总发送频率
        last_time = datetime.datetime.now() - self.last_email_sent_time
        if last_time < self.SERVER_RESEND_TIME:
            return 429, f"服务器繁忙，请等待{self.SERVER_RESEND_TIME - last_time}秒后再试", None
        
        # 生成6位数字验证码
        verification_code = ''.join(random.choices('0123456789', k=6))
        
        # 创建邮件对象
        msg = EmailMessage()
        msg["Subject"] = "黑名单系统 验证码"
        msg["From"] = self.email
        msg["To"] = recv_email
        
        # 使用HTML格式邮件内容
        msg.set_content(f"您正在<u>黑名单系统</u>注册账号或修改密码，您的验证码是: <b>{verification_code}</b>。验证码10分钟有效，请勿泄露给他人。", subtype="html")
        
        try:
            # 创建SMTP连接
            with smtplib.SMTP(self.SMTP_SERVER, self.SMTP_PORT) as server:
                server.starttls()  # 启用TLS加密
                server.login(self.email, self.auth_code)
                server.send_message(msg)
            
            # 记录验证码
            self.reg(recv_email, verification_code)
            return 200, "验证码已发送至邮箱，请注意查收", None
        
        except Exception as e:
            return 500, f"验证码发送失败: {str(e)}", None

    def get_user(self, qq_id):
        '''检查该用户是否已经注册'''
        return self.user_dict.get(qq_id, None)

    def verify(self, recv_email, unique_id, nickname, password, verification_code):
        """验证验证码接口，用于修改个人信息"""
        status = self.check(recv_email, verification_code)
        if status == 0:
            return 401, "验证码无效或已过期", None
        if status == 1:
            return 401, "验证码错误次数过多，请重新发送验证码", None
        try:
            conn = sqlite3.connect(static_export_class.black_list_db_path, detect_types=0, uri=True)
            cursor = conn.cursor()
            # 检查是否是qq邮箱，否则拒绝注册
            qq_id = recv_email.split('@')[0]
            if not qq_id.isdigit():
                return 400, "请使用旧版QQ邮箱注册", None
            # 检查unique_id有效性
            if not unique_id.isdigit():
                return 400, "无效的unique_id", None
            # 检查nickname有效性
            if len(nickname) > 31:
                return 400, "昵称过长", None
            # 检查密码
            old_password = self.user_dict[qq_id][4]
            old_nickname = self.user_dict[qq_id][3]
            user_type = self.user_dict[qq_id][2]
            password_hash = ""
            if password:
                if not self.verify_password(password):
                    return 400, "密码不符合要求", None
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            else:
                password_hash = old_password
            # 更新用户信息
            cursor.execute("UPDATE user_info SET unique_id=?, nickname=?, password=? WHERE qq_id=?", (unique_id, nickname, password, qq_id))
            self.user_dict[qq_id] = (qq_id, unique_id, user_type, nickname, password_hash)
            del self.user_name_to_id[old_nickname]
            self.user_name_to_id[nickname] = unique_id
            conn.commit()
            cursor.close()
            conn.close()
            return 200, "已注册，资料已更新", None
        except Exception as e:
            return 500, f"失败: {str(e)}", None
        
    def search(self, keyword, page, limit):
        '''搜索黑名单所有字段，page从1开始'''
        self.prepare()
        if keyword == self.result_keyword:
            return self.result[page*limit-limit:page*limit]
        self.result = []
        self.result_keyword = keyword
        for uid, blacklist_list in self.blacklist.items():
            for item in blacklist_list:
                if keyword in str(item):
                    self.result.append(item)
        return self.result[page*limit-limit:page*limit]



if __name__ == '__main__':
    '''运行本函数可以将xlsx迁移到空白的数据库'''
    obj = static_export_class()
    obj.prepare()
    obj.export_black_list_to_db()