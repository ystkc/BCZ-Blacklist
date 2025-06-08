import secrets
import re
import os
import sqlite3
import bcrypt
import openpyxl
import logging
import zipfile
from pydantic import BaseModel

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

guest_user = User(qq_id=0, unique_id=0, type=USER_TYPE_GUEST, nickname='访客', password='')

TABLE_TYPE_TOWN = 1
TABLE_TYPE_KING = 2
TABLE_TYPE_ACME = 3
TABLE_TYPE_STR_MAP = {
    TABLE_TYPE_TOWN: '城区黑名单',
    TABLE_TYPE_KING: '王者黑名单',
    TABLE_TYPE_ACME: '百强黑名单'
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
            'type': USER_TYPE_STR_MAP[user_type],
            'modify_other_users': True if user_type == USER_TYPE_ADMIN else False, # 管理员可以修改其他用户信息和改变其他用户类型
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
    
    def reason_name_to_id(self, reason_name: str | list[str], add_unknown: bool = False) -> list[int]:
        '''根据原因名称获取原因ID'''
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
    
    def reason_id_to_name(self, reason_id: list[int]) -> str:
        '''根据原因ID获取原因名称'''
        if not reason_id:
            return ''
        reasons = []
        for id in reason_id:
            if id in self.reason_id_lookup:
                reasons.append(self.reason_id_lookup[id])
            else:
                raise Exception(f"未知原因ID：{id}")
        result = ','.join(reasons)
        return result
    
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
        for row in user_list:
            self.user_dict[row[0]] = User(qq_id=row[0], unique_id=row[1], type=row[2], nickname=row[3], password=row[4])
            self.user_name_to_id[row[3]] = row[0]
        cursor.close()
        self.logger.info("用户信息读取完成")
    
    def create_remember_token(self, qq_id, REMEMBER_ME_TIME):
        '''生成记住密码的token'''
        remember_token = secrets.token_urlsafe(32)
        token_hash = bcrypt.hashpw(remember_token.encode(), bcrypt.gensalt())
        self.redis_client.setex(f"rmb:{qq_id}", REMEMBER_ME_TIME, token_hash)
        return remember_token
    
    def verify_remember_token(self, qq_id, token):
        '''验证记住密码的token'''
        token_hash = self.redis_client.get(f"rmb:{qq_id}")
        if bcrypt.checkpw(token.encode(), token_hash):
            return True
        else:
            return False
        

    def check_exist(self, uid, create_time):
        '''检查(uid, create_time)是否已经存在于黑名单，也就是唯一记录(无论table_id)'''
        return uid in self.blacklist and create_time in self.blacklist[uid]
    
    def repair_blacklist(self):
        '''自动修复黑名单中的无主数据，应该在管理员确认没有昵称被冒用后调用'''
        for uid, create_time_dict in self.blacklist.items():
            for create_time, tp in create_time_dict.items():
                recorder_qq_id = tp[6]
                if recorder_qq_id is None:
                    recorder_qq_id = self.user_name_to_id.get(tp[5], None)
                    if recorder_qq_id: # 修复成功
                        self.update_blacklist(uid, create_time, tp[2], tp[3], tp[4], tp[5], recorder_qq_id, tp[7], tp[8], tp[9])
        self.export_black_list_to_db()


    
    def update_blacklist(self, uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id, save_db=False):
        '''更新黑名单'''
        old_tp = None
        if self.check_exist(uid, create_time):
            old_tp = self.blacklist[uid][create_time]
        if uid not in self.blacklist:
            self.blacklist[uid] = {}
        tp = (uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id)
        id = (uid, create_time)
        self.blacklist[uid][create_time] = tp
        if recorder_qq_id:
            if recorder_qq_id not in self.blacklist_recorder:
                self.blacklist_recorder[recorder_qq_id] = {}
            self.blacklist_recorder[recorder_qq_id][id] = tp
        if old_tp != tp:
            if save_db:
                self.update_db(uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id)
            else:
                self.blacklist_buffer.append(tp)

    def get_target_auth_info(self, uid, create_time):
        '''获取目标黑名单的创建者id'''
        if self.check_exist(uid, create_time):
            tp = self.blacklist[uid][create_time]
            return tp[5] # recorder_qq_id也可能是None
        return -1
    
    def delete_blacklist(self, uid, create_time, operator_qq_id, operator_type):
        '''删除黑名单'''
        if self.check_exist(uid, create_time):
            tp = self.blacklist[uid][create_time]
            recorder_qq_id = tp[5]
            if operator_type != USER_TYPE_ADMIN:
                if recorder_qq_id != operator_qq_id or recorder_qq_id is None:
                    raise Exception("你只能删除自己创建的记录")
            id = (uid, create_time)
            if tp[6] in self.blacklist_recorder:
                del self.blacklist_recorder[tp[6]][id]
            del self.blacklist[uid][create_time]
        else:
            raise Exception(f"不存在的黑名单记录：{uid} {create_time}")

    def read_blacklist_db(self, conn: sqlite3.Connection):
        '''从数据库中读取黑名单（合并到内存）'''
        self.logger.info("正在读取 黑名单数据库")
        cursor = conn.cursor()
        cursor.execute("SELECT uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id FROM blacklist")
        blacklist_list = cursor.fetchall()
        for row in blacklist_list:
            self.update_blacklist(row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9])
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
            self.update_blacklist(uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, TABLE_TYPE_KING)

    def __init__(self, blacklist_db_path):
        self.logger = logging.getLogger(__name__)
        self.hash_index = 0
        self.hash_dict = {}
        self.blacklist = {}
        self.blacklist_buffer = []
        self.blacklist_recorder = {}
        self.last_email_sent_time = 0
        self.email_cache = {}  # 邮箱验证码缓存
        self.result = []
        self.reason_dict = {}
        self.reason_id_lookup = {}
        self.reason_buffer = []
        self.reason_max_id = 0
        self.result_keyword = ""
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
            password TEXT -- 管理员可以添加password为空的用户以便后续注册后直接获得相应身份组
        )''')
        conn.commit()
        cursor.close()
        conn.close()
        self.__ready = False
        self.logger.info("黑名单数据库初始化完成")
    
    def verify_password(self, password):
        '''检查密码是否符合要求(密码长度至少8位，包含数字和字母)'''
        if len(password) < 8:
            return False
        if not re.search(r"[0-9]+", password):
            return False
        if not re.search(r"[a-zA-Z]+", password):
            return False
        return True
    
    def login(self, qq_id, password):
        '''登录接口'''
        target_user = self.user_dict.get(qq_id, None)
        if not target_user:
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
        old_password = self.user_dict[qq_id]['password']
        old_nickname = self.user_dict[qq_id]['nickname']
        user_type = self.user_dict[qq_id]['type']
        if not new_type:
            new_type = user_type
        password_hash = ""
        if password:
            if not self.verify_password(password):
                raise Exception("密码不符合要求")
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        else:
            password_hash = old_password
        # 更新用户信息
        conn = sqlite3.connect(self.blacklist_db_path, detect_types=0, uri=True)
        cursor = conn.cursor()
        cursor.execute("UPDATE user_info SET unique_id=?, type=?, nickname=?, password=? WHERE qq_id=?", (unique_id, new_type, nickname, password_hash, qq_id))
        
        self.user_dict[qq_id] = User(qq_id=qq_id, unique_id=unique_id, type=new_type, nickname=nickname, password=password_hash)
        del self.user_name_to_id[old_nickname]
        self.user_name_to_id[nickname] = unique_id
        conn.commit()
        cursor.close()
        conn.close()
        

    def get_user(self, qq_id):
        '''检查该用户是否已经注册'''
        return self.user_dict.get(qq_id, None)

    
    def search(self, keyword, page, limit):
        '''搜索黑名单所有字段，page从1开始'''
        if keyword == self.result_keyword:
            return self.result[page*limit-limit:page*limit]
        self.result = []
        self.result_keyword = keyword
        for uid, blacklist_list in self.blacklist.items():
            for item in blacklist_list:
                if keyword in str(item):
                    self.result.append(item)
        return self.result[page*limit-limit:page*limit]

    def update_db(self, uid, create_time, nickname, date, reason_id_list:list, recorder, recorder_qq_id, remark, last_edit_time, table_id):
        '''添加黑名单（外部已经检查过，此处直接添加）'''
        conn = sqlite3.connect(self.blacklist_db_path, detect_types=0, uri=True)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO blacklist (uid, create_time, nickname, date, reason, recorder, recorder_qq_id, remark, last_edit_time, table_id) VALUES (?,?,?,?,?,?,?,?,?,?)", (uid, create_time, nickname, date, str(reason_id_list).replace(' ',''), recorder, recorder_qq_id, remark, last_edit_time, table_id))
        conn.commit()
        cursor.close()
        conn.close()

    def get_my_records(self, qq_id):
        '''获取该用户添加的黑名单记录（）'''
        return self.blacklist_recorder.get(qq_id, [])
    
    def get_reasons(self):
        '''获取所有原因的键值对'''
        return self.reason_id_lookup

if __name__ == '__main__':
    '''运行本函数可以将xlsx迁移到空白的数据库'''
    obj = blacklist_server_class('./blacklist.db')
    obj.prepare('./blacklist.xlsx')
    obj.export_black_list_to_db()