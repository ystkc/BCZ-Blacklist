import datetime
import secrets
import re
import os
import sqlite3
import time
import bcrypt
import openpyxl
import logging
import zipfile
from pydantic import BaseModel

MAX_LOG_CNT = 1000 # 日志最大条数

USER_TYPE_GUEST = 0
USER_TYPE_NORMAL = 1
USER_TYPE_KING = 2
USER_TYPE_ACME = 3
USER_TYPE_ADMIN = 99
USER_TYPE_STR_MAP = {
    USER_TYPE_GUEST: '访客',
    USER_TYPE_NORMAL: '普通成员/非王者班长',
    USER_TYPE_KING: '王者班长',
    USER_TYPE_ACME: '百强班长',
    USER_TYPE_ADMIN: '管理员'
}

class User(BaseModel):
    qq_id: int
    unique_id: int
    type: int
    nickname: str
    password: str
    session_expired: bool = False

guest_user = User(qq_id=0, unique_id=0, type=USER_TYPE_GUEST, nickname='请登录', password="")
system_user = User(qq_id=-1, unique_id=0, type=USER_TYPE_GUEST, nickname='系统管理员', password="") # 此帐号不应注册或登录，仅用于标记系统的操作

TABLE_TYPE_TOWN = 1
TABLE_TYPE_KING = 2
# TABLE_TYPE_ACME = 3
TABLE_TYPE_STR_MAP = {
    TABLE_TYPE_TOWN: '城区黑名单',
    TABLE_TYPE_KING: '王者黑名单',
    # TABLE_TYPE_ACME: '百强黑名单'
}

OPERATION_TYPE_ADD = 1
OPERATION_TYPE_DELETE = 2
OPERATION_TYPE_MODIFY_TO = 3
OPERATION_TYPE_MODIFY_FROM = 4
OPERATION_TYPE_RECOVER = 5
OPERATION_TYPE_REGISTER = 6
OPERATION_TYPE_STR_MAP = {
    OPERATION_TYPE_ADD: '新增',
    OPERATION_TYPE_DELETE: '删除',
    OPERATION_TYPE_MODIFY_TO: '修改',
    OPERATION_TYPE_MODIFY_FROM: '修改前',
    OPERATION_TYPE_RECOVER: '已撤销',
    OPERATION_TYPE_REGISTER: '注册'
}

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


class blacklist_server_class:
    
    def get_permission(self, user_type):
        '''获取用户权限组名称和可以编辑的表名称'''
        result = {
            'type': user_type,
            'type_name': USER_TYPE_STR_MAP[user_type],
            'modify_other_users': True if user_type == USER_TYPE_ADMIN else False, # 管理员可以修改其他用户信息和改变其他用户类型
            'login_required': True if user_type == USER_TYPE_GUEST else False, # 访客需要登录
            'has_admin': self.has_admin, # 是否有管理员，如果没有，则要求立即注册一个管理员
            'admin_alert': '没有检测到管理员账号，请立即注册一个管理员账号' if not self.has_admin else '',
            'admin_notice': '<u><b>您正在注册管理员账号。请注意：管理员可以设置或取消其他管理员的权限，无论注册顺序先后</b></u>' if not self.has_admin else '',
            'tables': {}
        }
        for table_type, table_name in TABLE_TYPE_STR_MAP.items():
            if user_type > table_type:
                result['tables'][table_name] = table_type
        return result

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
    
    def reason_name_to_id(self, reason_name: str | list[str], add_unknown: bool = False) -> str:
        '''根据原因名称获取原因ID，返回id,id,id或空字符串'''
        if not reason_name:
            return ""
        reasons = reason_name.split(',') if type(reason_name) == str else reason_name
        result = []
        for reason in reasons:
            if reason in self.reason_dict:
                result.append(str(self.reason_dict[reason]))
            else:
                if add_unknown:
                    self.reason_max_id += 1
                    self.reason_dict[reason] = self.reason_max_id
                    self.reason_id_lookup[self.reason_max_id] = reason
                    self.reason_buffer.append((self.reason_max_id, reason))
                    result.append(str(self.reason_max_id))
                else:
                    raise Exception(f"未知原因：{reason}")
        result = ','.join(result)
        return result
    
    def reason_id_to_name(self, reason_id: list[int] | str) -> str:
        '''根据原因ID获取原因名称'''
        if not reason_id or len(reason_id) == 0:
            return ''
        if type(reason_id) == str:
            reason_id = reason_id.split(',')
        reasons = []
        for id in reason_id:
            if id == '':
                continue
            id = int(id)
            if id in self.reason_id_lookup:
                reasons.append(self.reason_id_lookup[id])
            else:
                raise Exception(f"未知原因ID：{id}")
        result = ','.join(reasons)
        return result
    
    def table_id_to_name(self, table_id):
        '''根据表ID获取表名称'''
        return TABLE_TYPE_STR_MAP.get(table_id, None)
    
    def read_reason(self, conn: sqlite3.Connection):
        '''从原因表格中读取原因的ID和名称'''
        self.logger.info("正在读取 原因配置")
        cursor = conn.cursor()
        self.reason_max_id = cursor.execute("SELECT MAX(reason_id) FROM reason").fetchone()[0] or 0
        cursor.execute("SELECT reason_id, reason_name FROM reason")
        reason_list = cursor.fetchall()
        for row in reason_list:
            self.reason_dict[row[1]] = row[0]
            self.reason_id_lookup[row[0]] = row[1]
        cursor.close()
        self.logger.info("原因配置读取完成")
    
    def read_user_info(self, conn: sqlite3.Connection):
        '''从数据库中读取用户信息'''
        self.logger.info("正在读取 用户信息")
        cursor = conn.cursor()
        cursor.execute("SELECT qq_id, unique_id, type, nickname, password FROM user_info")
        user_list = cursor.fetchall()
        self.user_dict = {}
        self.user_name_to_id = {}
        self.has_admin = False
        for row in user_list:
            if row[2] == USER_TYPE_ADMIN:
                self.has_admin = True
            self.user_dict[row[0]] = User(qq_id=row[0], unique_id=row[1], type=row[2], nickname=row[3], password=row[4])
            self.user_name_to_id[row[3]] = row[0]
        cursor.close()
        self.logger.info("用户信息读取完成")

    def check_exist(self, uid, create_time):
        '''检查(uid, create_time)是否已经存在于黑名单，也就是唯一记录(无论table_id)'''
        return uid in self.blacklist and create_time in self.blacklist[uid]

    def check_exist_user(self, qq_id):
        '''检查qq_id是否已经存在于用户表（未注册为游客，预注册密码为空，都可以用密码进行判断）'''
        result = self.user_dict.get(qq_id, guest_user)
        return result.password != ""
    
    def get_user(self, qq_id):
        '''获取该用户'''
        return self.user_dict.get(qq_id, None)
    
    def repair_blacklist(self):
        '''自动修复黑名单中的无主数据，应该在管理员确认没有昵称被冒用后调用'''
        for uid, create_time_dict in self.blacklist.items():
            for create_time, tp in create_time_dict.items():
                recorder_qq_id = tp[6]
                if recorder_qq_id is None:
                    recorder_qq_id = self.user_name_to_id.get(tp[5], None)
                    if recorder_qq_id: # 修复成功
                        self.update_blacklist(uid, create_time, tp[2], tp[3], tp[4], tp[5], recorder_qq_id, tp[7], tp[8], tp[9], system_user)
        self.export_black_list_to_db()

    def interpretT(self, timestamp):
        '''将时间戳转换为字符串'''
        return datetime.datetime.strftime(datetime.datetime.fromtimestamp(timestamp), '%Y/%m/%d %H:%M:%S')
    
    def chkdiff(self, old_tp, new_tp):
        '''检查两个tp是否相同(除了last_edit_time)'''
        if old_tp is None:
            return False
        for i in range(len(old_tp)):
            if old_tp[i] != new_tp[i] and i != 8:
                return False
        return True

    def update_blacklist(self, uid, create_time, nickname, date, reason_id_list, recorder, recorder_qq_id, remark, last_edit_time, table_id, user: User, save_db=False):
        '''更新黑名单'''
        old_tp = None
        operation = OPERATION_TYPE_MODIFY_TO
        if self.check_exist(uid, create_time):
            old_tp = self.blacklist[uid][create_time]
        else:
            operation = OPERATION_TYPE_ADD
        tp = (uid, create_time, nickname, date, reason_id_list, recorder, recorder_qq_id, remark, last_edit_time, table_id)
        id = (uid, create_time)
        if self.chkdiff(old_tp, tp):
            raise Exception(f"记录没有修改")
        if old_tp:
            # 记录修改前的记录
            reason = str(old_tp[4]).replace(' ','')
            self.blacklist_log.append((uid, create_time, old_tp[2], old_tp[3], reason, old_tp[5], old_tp[6], old_tp[7], old_tp[8], old_tp[9], OPERATION_TYPE_MODIFY_FROM, user.qq_id))
            if self.blacklist_log_cnt > MAX_LOG_CNT:
                self.blacklist_log.pop(0)
            else:
                self.blacklist_log_cnt += 1
        if uid not in self.blacklist:
            self.blacklist[uid] = {}
            self.blacklist_str[uid] = {}
        
        self.blacklist[uid][create_time] = tp
        self.blacklist_str[uid][create_time] = "".join([
            str(uid),
            self.interpretT(create_time),
            nickname if nickname else '',
            self.interpretT(date), 
            self.reason_id_to_name(reason_id_list.split(',')), 
            recorder if recorder else '', 
            str(recorder_qq_id) if recorder_qq_id else '',
            remark if remark else '', 
            self.interpretT(last_edit_time), 
            TABLE_TYPE_STR_MAP[table_id]])
        if recorder_qq_id:
            if recorder_qq_id not in self.blacklist_recorder:
                self.blacklist_recorder[recorder_qq_id] = {}
            self.blacklist_recorder[recorder_qq_id][id] = tp
        if recorder:
            if recorder not in self.blacklist_cnt:
                self.blacklist_cnt[recorder] = 0
            if not old_tp:
                self.blacklist_cnt[recorder] += 1
        if save_db:
            self.update_db(uid, create_time, nickname, date, reason_id_list, recorder, recorder_qq_id, remark, last_edit_time, table_id, operation, user)
        else:
            reason = str(reason_id_list).replace(' ','')
            self.blacklist_log.append((uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id, operation, user.qq_id))
            if self.blacklist_log_cnt > MAX_LOG_CNT:
                self.blacklist_log.pop(0)
            else:
                self.blacklist_log_cnt += 1
            self.blacklist_buffer.append(tp)

    def get_target_auth_info(self, uid, create_time):
        '''获取目标黑名单的创建者id'''
        if self.check_exist(uid, create_time):
            tp = self.blacklist[uid][create_time]
            return tp[6] # recorder_qq_id也可能是None
        return -1
    
    def delete_blacklist(self, uid, create_time, user: User):
        '''删除黑名单'''
        if self.check_exist(uid, create_time):
            uid, create_time, nickname, date, reason_id_list, recorder, recorder_qq_id, remark, last_edit_time, table_id = self.blacklist[uid][create_time]
            id = (uid, create_time)
            if recorder_qq_id in self.blacklist_recorder:
                del self.blacklist_recorder[recorder_qq_id][id] # 删除记录时用的是原记录者的qq_id
                self.blacklist_cnt[recorder] -= 1
            del self.blacklist[uid][create_time]
            del self.blacklist_str[uid][create_time]
            self.delete_from_db(uid, create_time, nickname, date, reason_id_list, recorder, recorder_qq_id, remark, last_edit_time, table_id, OPERATION_TYPE_DELETE, user)
            # 清除缓存
            self.result = []
            self.result_keyword = ""
        else:
            raise Exception(f"不存在的黑名单记录：{uid} {create_time}")

    def read_blacklist_db(self, conn: sqlite3.Connection):
        '''从数据库中读取黑名单（合并到内存）'''
        self.logger.info("正在读取 黑名单数据库")
        cursor = conn.cursor()
        cursor.execute("SELECT uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id FROM blacklist")
        blacklist_list = cursor.fetchall()
        for row in blacklist_list:
            self.update_blacklist(row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], system_user)
        cursor.close()
    
    def read_blacklist_xlsx(self, blacklist_xlsx_path):
        '''从xlsx文件中读取黑名单（合并到内存）'''
        if not os.path.exists(blacklist_xlsx_path):
            return
        self.logger.info("正在读取 黑名单 excel 文件")
        wb = openpyxl.load_workbook(blacklist_xlsx_path)
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
            nickname = (row[0].value)
            create_time = date = int(row[2].value.timestamp())
            recorder = (row[4].value)
            recorder_qq_id = self.user_name_to_id.get(row[4].value, None)
            
            if self.check_exist(uid, date):
                continue

            reason = ""
            if row[3].value is not None:
                reason = self.reason_name_to_id(row[3].value, add_unknown=True)
            
            remark = (row[5].value)

            if row[6].value is None:
                continue
            last_edit_time = row[6].value.timestamp()
            try:
                last_editor = (row[7].value)
            except:
                last_editor = ('无')
            try:
                first_editor = (row[8].value)
            except:
                first_editor = ('无')
            self.update_blacklist(uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, TABLE_TYPE_KING, system_user)

    def __init__(self, blacklist_db_path):
        self.logger = logging.getLogger(__name__)
        self.has_admin = False # 如果没有管理员，则要求立即注册一个
        self.blacklist = {}
        self.blacklist_str = {} # 每条记录的字符串形式，方便搜索
        self.blacklist_buffer = [] # 批量处理时的缓冲区
        self.blacklist_log = [] # 黑名单操作内存日志
        self.blacklist_log_cnt = 0 # 黑名单操作内存日志计数
        self.blacklist_recorder = {} # 按创建者分组的黑名单记录，方便用户查找自己的记录
        self.blacklist_cnt = {} # 记录每个用户记录的黑名单数量（按昵称统计，方便修复黑名单）
        self.last_email_sent_time = 0
        self.email_cache = {}  # 邮箱验证码缓存
        self.result = [] # 搜索结果缓存
        self.result_keyword = "" # 当前搜索结果缓存的关键字
        self.result_len = 0
        self.reason_dict = {} # 原因名称和ID的映射
        self.reason_id_lookup = {} # 原因ID和名称的映射
        self.reason_buffer = [] # 批量添加原因时的原因缓冲区
        self.reason_max_id = 0 # 最大原因ID，用于自动生成ID为新的原因
        self.blacklist_db_path = blacklist_db_path
        # 初始化数据库
        self.logger.info("正在初始化 黑名单数据库")
        conn = sqlite3.connect(self.blacklist_db_path, detect_types=0, uri=True)
        self.configure_database(conn)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS blacklist (
            uid INTEGER NOT NULL,
            create_time INTEGER NOT NULL, -- timestamp
            nickname TEXT,
            date INTEGER NOT NULL, -- timestamp
            reason TEXT,
            recorder TEXT,
            recorder_qq_id INTEGER,
            remark TEXT,
            last_edit_time INTEGER NOT NULL, -- timestamp
            table_id INTEGER NOT NULL,
         PRIMARY KEY (uid, create_time))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS reason (
            reason_id INTEGER PRIMARY KEY,
            reason_name TEXT NOT NULL UNIQUE
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_info (
            qq_id INTEGER PRIMARY KEY, -- 非hash，每个qq号只能对应一个账号，只填大号uid就好了
            unique_id INTEGER, -- 非hash
            type INTEGER, -- 0为管理员，1为普通用户，2为王者班长
            nickname TEXT, -- 非hash
            password BLOB -- 管理员可以添加password为空的用户以便后续注册后直接获得相应身份组
        )''')
        conn.commit()
        cursor.close()
        conn.close()
        self.__ready = False
        self.logger.info("黑名单数据库初始化完成")
    
    def login(self, qq_id, password):
        '''登录接口'''
        target_user = self.user_dict.get(qq_id, None)
        if not target_user or not target_user.password: # 未注册为游客，预注册密码为空
            return False
        if not bcrypt.checkpw(password.encode(), target_user.password.encode()):
            return False
        return True

    
    def prepare(self, blacklist_xlsx_path):
        if not self.__ready:
            self.logger.info("正在读取 黑名单数据")
            conn = sqlite3.connect(self.blacklist_db_path, detect_types=0, uri=True)
            self.read_reason(conn)
            self.read_user_info(conn) # 先读取用户信息以便修复旧数据
            self.read_blacklist_db(conn)
            self.read_blacklist_xlsx(blacklist_xlsx_path)
            self.__ready = True
            self.logger.info("黑名单数据读取完成")
    
    def export_black_list_to_db(self):
        '''导出黑名单到数据库(大规模修改时使用，方法：先使用update_blacklist的save_db选项为False，然后完毕后调用此函数)'''
        self.logger.info("正在保存黑名单到数据库")
        conn = sqlite3.connect(self.blacklist_db_path, detect_types=0, uri=True)
        self.configure_database(conn)
        cursor = conn.cursor()
        cursor.executemany("INSERT OR REPLACE INTO blacklist (uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id) VALUES (?,?,?,?,?,?,?,?,?,?)", self.blacklist_buffer)
        self.blacklist_buffer = []
        # 导出reason 表
        cursor.executemany("INSERT OR REPLACE INTO reason (reason_id, reason_name) VALUES (?,?)", self.reason_buffer)
        self.reason_buffer = []
        conn.commit()
        cursor.close()
        conn.close()
        self.logger.info("黑名单已经保存到数据库")

    def export_black_list_to_bin(self, black_list_assets):
        '''导出黑名单到静态json文件'''
        self.logger.info("正在写入 黑名单 json 文件")
        with open(black_list_assets, 'wb') as f:
            f.write(encoder(blacklist_server_class.flatten(blacklist_server_class.detach(self.blacklist))))
        with zipfile.ZipFile(f"{black_list_assets}.zip", 'w', zipfile.ZIP_DEFLATED) as f:
            f.write(black_list_assets, arcname=black_list_assets)
        self.logger.info("黑名单导出完成")
    
    def update_user(self, qq_id, unique_id, nickname, password, new_type):
        '''更新用户信息'''
        # 检查密码
        old_password_hash = ""
        old_nickname = None
        old_unique_id = None
        user_type = None
        user = self.user_dict.get(qq_id, None)
        if user:
            old_password_hash = user.password # 有可能是管理员预注册用户，只有部分信息，需要更新密码
            old_nickname = user.nickname
            old_unique_id = user.unique_id
            user_type = user.type
        if not new_type:
            new_type = user_type
        if not nickname:
            nickname = old_nickname
        if not unique_id:
            unique_id = old_unique_id
        if not old_password_hash and password: # 正式注册
            self.blacklist_log.append((unique_id, int(time.time()), nickname, None, None, "", None, USER_TYPE_STR_MAP[new_type], int(time.time()), None, OPERATION_TYPE_REGISTER, qq_id))
            if self.blacklist_log_cnt > MAX_LOG_CNT:
                self.blacklist_log.pop(0)
            else:
                self.blacklist_log_cnt += 1
        
        password_hash = ""
        if password:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        else:
            password_hash = old_password_hash.encode('utf-8')
        # 更新用户信息
        self.logger.info(f"更新用户 {qq_id} {unique_id} {nickname} {password} {new_type}")
        conn = sqlite3.connect(self.blacklist_db_path, detect_types=0, uri=True)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO user_info (unique_id, type, nickname, password, qq_id) VALUES (?,?,?,?,?)", (unique_id, new_type, nickname, password_hash, qq_id))
        conn.commit()
        cursor.close()
        conn.close()
        if new_type == USER_TYPE_ADMIN:
            self.has_admin = True
        self.user_dict[qq_id] = User(qq_id=qq_id, unique_id=unique_id, type=new_type, nickname=nickname, password=password_hash)
        if old_nickname:
            del self.user_name_to_id[old_nickname]
        self.user_name_to_id[nickname] = qq_id

    def search(self, keyword, page, limit):
        '''搜索黑名单所有字段，page从1开始(可能效率有点低下，以后改进)'''
        if keyword == self.result_keyword:
            page_max = (self.result_len-1)//limit+1
            page = max(1, min(page, page_max))
            return {'result': self.result[page*limit-limit:page*limit], 'page_max': page_max, 'page': page}
        self.result = []
        self.result_keyword = keyword
        for uid, str_list in self.blacklist_str.items():
            for create_time, item in str_list.items():
                if keyword in item:
                    self.result.append(self.blacklist[uid][create_time])
        self.result_len = len(self.result)
        return self.search(keyword, page, limit) # 使用桐一个结果构造器

    def update_db(self, uid, create_time, nickname, date, reason_id_list:list, recorder, recorder_qq_id, remark, last_edit_time, table_id, operation, user: User):
        '''添加黑名单（外部已经检查过，此处直接添加）'''
        conn = sqlite3.connect(self.blacklist_db_path, detect_types=0, uri=True)
        cursor = conn.cursor()
        reason = str(reason_id_list).replace(' ','')
        cursor.execute("INSERT OR REPLACE INTO blacklist (uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id) VALUES (?,?,?,?,?,?,?,?,?,?)", (uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id))
        self.blacklist_log.append((uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id, operation, user.qq_id))
        if self.blacklist_log_cnt > MAX_LOG_CNT:
            self.blacklist_log.pop(0)
        else:
            self.blacklist_log_cnt += 1
        conn.commit()
        cursor.close()
        conn.close()
        # 清除缓存
        self.result = []
        self.result_keyword = ""

    def delete_from_db(self, uid, create_time, nickname, date, reason_id_list:list, recorder, recorder_qq_id, remark, last_edit_time, table_id, operation, user: User):
        '''删除黑名单（外部已经检查过，此处直接删除）'''
        conn = sqlite3.connect(self.blacklist_db_path, detect_types=0, uri=True)
        cursor = conn.cursor()
        reason = str(reason_id_list).replace(' ','')
        cursor.execute("DELETE FROM blacklist WHERE uid=? AND create_time=?", (uid, create_time))
        self.blacklist_log.append((uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id, operation, user.qq_id))
        if self.blacklist_log_cnt > MAX_LOG_CNT:
            self.blacklist_log.pop(0)
        else:
            self.blacklist_log_cnt += 1
        conn.commit()
        cursor.close()
        conn.close()

    def get_count_list(self):
        '''获取记录过黑名单的用户(昵称,qq_id)，按记录的多少排序'''
        # 先将所有(用户nickname,qq_id,记录数)组成列表
        result = []
        for nickname, cnt in self.blacklist_cnt.items():
            result.append((self.user_name_to_id.get(nickname), nickname, cnt))
        # 按记录数排序
        result.sort(key=lambda x:x[2], reverse=True)
        return result

    def get_my_records(self, qq_id, page, limit):
        '''获取该用户添加的黑名单记录（page从1开始）'''
        tot = list(self.blacklist_recorder.get(qq_id, {}).values())
        page_max = (len(tot)-1)//limit+1
        page = max(1, min(page, page_max))
        return {'result': tot[page*limit-limit:page*limit], 'page_max': page_max, 'page': page}
    
    def get_dicts(self):
        '''获取所有原因、表、操作类型的键值对'''
        return {
            'reasons': self.reason_id_lookup,
            'tables': TABLE_TYPE_STR_MAP,
            'operations': OPERATION_TYPE_STR_MAP
        }
    
    def get_register_type(self, qq_id):
        '''根据用户提供的邮箱判断即将注册的类型'''
        if not self.has_admin:
            return USER_TYPE_ADMIN, USER_TYPE_STR_MAP[USER_TYPE_ADMIN]
        tp = self.user_dict.get(qq_id, None)
        if not tp:
            return USER_TYPE_NORMAL, USER_TYPE_STR_MAP[USER_TYPE_NORMAL]
        return tp.type, USER_TYPE_STR_MAP[tp.type]

    def get_latest_logs(self, limit, page, max_tot):
        '''获取最近的修改日志'''
        max_index = self.blacklist_log_cnt
        if not max_tot:
            max_tot = max_index
        page_max = (min(max_index, max_tot)-1)//limit+1
        page = max(1, min(page, page_max))
        index_start = max(0, max(max_index - max_tot, max_index - limit*(page)))
        index_end = max_index - limit*(page-1)
        result = self.blacklist_log[index_start:index_end]
        result.reverse()
        return {'result': result, 'page_max': page_max, 'page': page}

if __name__ == '__main__':
    '''运行本函数可以将xlsx迁移到空白的数据库'''
    obj = blacklist_server_class('./blacklist.db')
    obj.prepare('./blacklist.xlsx')
    obj.export_black_list_to_db()