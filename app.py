
from contextlib import asynccontextmanager
import threading
import time
import traceback
import datetime
from email.message import EmailMessage
import json
import os
import random
import re
import smtplib
import bcrypt
import jwt
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from src.blacklist_utils import blacklist_server_class, User, guest_user, USER_TYPE_ADMIN, USER_TYPE_GUEST, USER_TYPE_KING
from fastapi import FastAPI, Request, Response
from fastapi import Depends, HTTPException, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.security import OAuth2PasswordRequestForm
import logging
from pydantic import BaseModel, SecretStr
import secrets
from queue import Queue

SESSION_EXPIRE_TIME = 300 # 会话过期时间，单位秒
REMEMBER_ME_TIME = 3600*24*14 # 记住我选项的有效期，单位秒
DEFAULT_LIMITS = ["3/second", "30/minute", "300/hour"] # 默认访问速率限制
MAX_STR_LEN = 31 # 黑名单每个字符串的最大长度
MAX_REMARK_LEN = 255 # 黑名单备注的最大长度

ACCOUNT_REGISTER = 1
ACCOUNT_RESET_PASSWORD = 2
ACCOUNT_MODIFY_INFO = 3
ACCOUNT_OPERATIONS = {
    ACCOUNT_REGISTER: '注册',
    ACCOUNT_RESET_PASSWORD: '重置密码',
    ACCOUNT_MODIFY_INFO: '修改资料',
}


USER_RESEND_TIME = 60 # 同一用户连续两次发送验证码的最短间隔时间
SERVER_RESEND_TIME = 20 # 服务器连续两次发送验证码的最短间隔时间
EXPIRE_TIME = 600 # 验证码有效期（秒）
MAX_VERIFY_FAIL_COUNT = 3 # 最大验证码错误次数

DEFAULT_MAIL = "[necessary]your_email@qq.com"
DEFAULT_AUTH_CODE = "[necessary]your_authorization_code"


EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

class ModelRedis:
    '''由于目前并发要求不高，为降低资源占用，暂时手动实现部分redis功能'''
    DAEMON_INTERVAL = 2 # 过期key扫描间隔（秒）
    def __init__(self):
        self.logger = logging.getLogger("ModelRedis")
        self.storage = {} # key:subkey -> (value, expire_timestamp)
        self.__stop = False
        self.expire_queue = Queue() # 过期key队列 (key:subkey, expire_timestamp)
        self.nearest_expire_key = None # 最近即将过期的key 
        self.nearest_expire_timestamp = 0 # 最近即将过期的key的过期时间戳
        threading.Thread(target=self.__daemon, daemon=True).start()

    def __daemon(self):
        '''清理过期session，每秒检查一次最接近过期的session
        漏洞：如果有一个key被反复延时，会导致队列中积压过多的过期key，不影响功能但消耗内存。但是本程序不需要延时，故不考虑。'''
        while not self.__stop:
            try:
                timestamp = int(time.time())
                while not self.expire_queue.empty() and timestamp >= self.nearest_expire_timestamp:
                    # 最近即将过期的key已经过期，且有下一个即将过期的key，处理然后覆盖
                    true_nearest_expire_tp = self.storage.get(self.nearest_expire_key)
                    if not true_nearest_expire_tp: # 有可能已经被get函数发现过期并删除了
                        self.nearest_expire_key, self.nearest_expire_timestamp = self.expire_queue.get()
                        continue
                    true_nearest_expire_timestamp = true_nearest_expire_tp[1]
                    if true_nearest_expire_timestamp <= timestamp: # 有可能这个key的过期时间被更新了，所以要再判断一次
                        del self.storage[self.nearest_expire_key]
                        self.nearest_expire_key, self.nearest_expire_timestamp = self.expire_queue.get()
                    else:
                        self.nearest_expire_timestamp = true_nearest_expire_timestamp
                        break
                # self.logger.debug(f"{self.nearest_expire_key} ({self.nearest_expire_timestamp - timestamp}s) \n {self.storage}")
                time.sleep(self.DAEMON_INTERVAL)
            except Exception as e:
                self.logger.error(f"redis daemon error: {e}")
    
    def setex(self, key: str, expire_time: int, value: str):
        '''设置key-value，并设置过期时间'''
        expire_timestamp = int(time.time()) + expire_time
        self.storage[key] = (value, expire_timestamp)
        self.expire_queue.put((key, expire_timestamp))
        return "OK"
    
    def get(self, key: str):
        '''获取key-value'''
        value_tp = self.storage.get(key)
        if not value_tp:
            return None
        value, expire_timestamp = value_tp
        if expire_timestamp <= int(time.time()):
            del self.storage[key]
            return None
        return value
    
    def delete(self, key: str):
        '''删除key-value'''
        if key in self.storage:
            del self.storage[key]
    
    def ttl(self, key: str):
        '''获取key的剩余过期时间'''
        value_tp = self.storage.get(key)
        if not value_tp:
            return -2
        value, expire_timestamp = value_tp
        if expire_timestamp == -1:
            return -1
        if expire_timestamp <= int(time.time()):
            del self.storage[key]
            return -2
        return expire_timestamp - int(time.time())
    
    def incr(self, key: str):
        '''自增key的值'''
        value_tp = self.storage.get(key)
        if not value_tp:
            self.storage[key] = (1, -1)
            return 1
        value, expire_timestamp = value_tp
        if not isinstance(value, int):
            raise ValueError("value must be int")
        if expire_timestamp <= int(time.time()):
            self.storage[key] = (1, -1)
            return 1
        self.storage[key] = (int(value)+1, expire_timestamp)
        return int(value)+1

    def quit(self):
        '''不是QUIT命令，只是停止daemon线程以便优雅的退出'''
        self.__stop = True

    def flushall(self):
        '''清空所有key-value，用于在管理员测试覆盖数据库时退出所有用户和会话'''
        self.storage.clear()
        self.expire_queue.queue.clear()
        self.nearest_expire_key = None
        self.nearest_expire_timestamp = 0


# 原生redis：
# import redis
# redis_pool = redis.ConnectionPool(host='localhost', port=6379, db=0, decode_responses=True)
# redis_client = redis.Redis(connection_pool=redis_pool)

# 手动redis：
redis_client = ModelRedis()

class Config():
    BLACKLIST_CONFIG_PATH = './blacklist.json' # 黑名单配置路径（现在仅储存授权码）
    def __init__(self):
        if not os.path.exists(self.BLACKLIST_CONFIG_PATH):
            self.config = {}
        else:
            with open(self.BLACKLIST_CONFIG_PATH, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        self.update_config(self.config)

    def interpretBool(self, input):
        if type(input) == str:
            return input.lower() in ['true', 'True', '1', 'yes']
        elif type(input) == int:
            return input == 1
        else:
            return bool(input)

    def update_config(self, config: dict):
        original_copy = self.config.copy()
        original_copy.update(config)
        config = original_copy
        self.blacklist_xlsx_path = config.get('blacklist_xlsx_path', './blacklist.xlsx') # 黑名单excel文件路径（只读）空置或文件无效时则跳过导入
        self.blacklist_db_path = config.get('blacklist_db_path', './blacklist.db') # 黑名单数据库路径（读&写）
        self.blacklist_assets = config.get('blacklist_assets', './assets/black_list.bin') # 黑名单数据路径（仅导出）
        self.smtp_server = config.get('smtp_server', 'smtp.qq.com') # SMTP服务器地址
        self.smtp_port = config.get('smtp_port', 587) # SMTP服务器端口
        self.smtp_email = config.get('smtp_email', DEFAULT_MAIL) # SMTP服务器用户名
        self.smtp_auth_code = config.get('smtp_auth_code', DEFAULT_AUTH_CODE) # SMTP服务器密码
        self.host = config.get('host', '127.0.0.1') # 服务器监听地址
        self.port = config.get('port', 8870) # 服务器监听端口

        # 以下是调试设置，已经默认配置为生产环境设置
        self.LOGGING_LEVEL = config.get('LOGGING_LEVEL', 'INFO') # 日志等级
        self.IS_HTTPS = self.interpretBool(config.get('IS_HTTPS', True))  # 强烈建议仅本地调试时设置IS_HTTPS=False
        self.DEBUG_DO_NOT_SEND_EMAIL = self.interpretBool(config.get('DEBUG_DO_NOT_SEND_EMAIL', False)) # 调试模式下不发送邮件
        self.DEBUG_AVATAR_QQ_URL = self.interpretBool(config.get('DEBUG_AVATAR_QQ_URL', True)) # 调试模式下不使用QQ头像
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
            with open(self.BLACKLIST_CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=4)
                print("黑名单配置已更新")

        
config = Config()
logger = logging.getLogger(__name__)


class VerifyCodeRequest(BaseModel):
    recv_email: str

class VerifyRequest(BaseModel):
    recv_email: str
    unique_id: str
    nickname: str
    password: str
    verify_code: str

class LoginForm(BaseModel):
    qq_id: int
    password: SecretStr
    remember_me: bool = False


logging.basicConfig(
    format='%(asctime)s [%(name)s][%(levelname)s] %(message)s',
    level=logging.DEBUG if config.LOGGING_LEVEL == 'DEBUG' else logging.INFO
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    redis_client.quit()
    

jwt_secret = secrets.token_urlsafe(32) # 每次重启或有人修改密码时都会改变
app = FastAPI(lifespan=lifespan)
limiter = Limiter(key_func=get_remote_address, default_limits=DEFAULT_LIMITS)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.mount("/static/css", StaticFiles(directory="static/css"), name="css")
app.mount("/static/js", StaticFiles(directory="static/js"), name="js")
app.mount("/static/fonts", StaticFiles(directory="static/fonts"), name="fonts")
app.mount("/static/img", StaticFiles(directory="static/img"), name="img")
@app.get('/favicon.ico') # 用mount会307+404，应该是只有文件夹可以
async def favicon(request: Request):
    return FileResponse('static/favicon.ico')

blacklist_server = blacklist_server_class(config.blacklist_db_path)
try:
    blacklist_server.prepare(config.blacklist_xlsx_path)
except Exception as e:
    logger.error(f"初始化黑名单服务器失败：{e}")
templates = Jinja2Templates(directory="templates")

@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return restful(guest_user, 429, f"服务器繁忙")

@app.get('/')
async def index(request: Request, response: Response):
    '''主页'''
    return templates.TemplateResponse("index.html", {"request": request})

def decodeJWT(session_id) -> User:
    '''解码JWT'''
    try:
        decoded = jwt.decode(session_id, jwt_secret, algorithms=['HS256'])
        if int(time.time()) > int(decoded['e']): # 过期
            return None
        result = User(qq_id=decoded['q'], unique_id=decoded['u'], type=decoded['t'], nickname=decoded['n'], password="")
        return result
    except:
        return None

def encodeJWT(user: User) -> str:
    '''编码JWT'''
    expire_timestamp = int(time.time()) + SESSION_EXPIRE_TIME
    payload = {'q': user.qq_id, 'u': user.unique_id, 't': user.type, 'n': user.nickname, 'e': expire_timestamp}
    result = jwt.encode(payload, jwt_secret, algorithm='HS256')
    return result

def refresh_session(user: User, response: Response, remember_me: bool = False) -> Response:
    '''创建session和remember_token'''
    if user.type == USER_TYPE_GUEST:
        return response
    if user.session_expired: # 重新生成JWT令牌
        session_id = encodeJWT(blacklist_server.get_user(user.qq_id))
        response.set_cookie(key='session_id', value=session_id, httponly=True, secure=config.IS_HTTPS, samesite='strict', max_age=None) # 浏览器关闭后自动删除
        
    def create_remember_token(qq_id, REMEMBER_ME_TIME):
        '''生成记住密码的token'''
        remember_token = secrets.token_urlsafe(32)
        token_hash = bcrypt.hashpw(remember_token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        redis_client.setex(f"rmb:{qq_id}", REMEMBER_ME_TIME, token_hash) # 用于修改密码时登出旧的session
        redis_client.setex(f"rmb_uid:{token_hash}", REMEMBER_ME_TIME, qq_id) # 用于验证令牌
        return remember_token, token_hash
    
    if remember_me: # 只有在remember_me为True也就是登录时勾选了自动登录才会创建remember_token
        remember_token, token_hash = create_remember_token(user.qq_id, REMEMBER_ME_TIME)
        response.set_cookie(key='remember_token', value=remember_token, httponly=True, secure=config.IS_HTTPS, samesite='strict', max_age=REMEMBER_ME_TIME) # 设置httponly=False，可以用JavaScript读取
        response.set_cookie(key='hashed_token', value=token_hash, httponly=True, secure=config.IS_HTTPS, samesite='strict', max_age=REMEMBER_ME_TIME)
    return response

def get_current_user(request: Request) -> User:
    """获取当前用户"""
    # 首先尝试从会话Cookie获取session_id(JWT)
    session_id = request.cookies.get("session_id")
    if session_id:
        user = decodeJWT(session_id.encode())
        if user:
            return user
    
    def verify_remember_token(token_hash, remember_token) -> int | None:
        '''验证记住密码的token'''
        if token_hash and remember_token and bcrypt.checkpw(remember_token.encode(), token_hash.encode()):
            uid = redis_client.get(f"rmb_uid:{token_hash}")
            return uid

    # 如果会话无效，尝试使用记住令牌重新认证
    token_hash = request.cookies.get("hashed_token")
    remember_token = request.cookies.get("remember_token")
    uid = verify_remember_token(token_hash, remember_token)
    if uid:
        user_data = blacklist_server.get_user(uid)
        if user_data:
            user_data.session_expired = True
            return user_data
        
    # 如果没有有效会话或记住令牌：访客模式
    return guest_user

# === API端点 ===
@app.post("/bapi/login")
@limiter.limit("5/minute")
async def login(request: Request, form: LoginForm):
    '''登录接口'''
    try:
        qq_id = int(form.qq_id)
        if blacklist_server.login(qq_id, form.password.get_secret_value()):
            user = blacklist_server.get_user(qq_id)
            user.session_expired = True
            return restful(user, 200, "登录成功", None, form.remember_me)
        return restful(guest_user, 401, "无效的用户名或密码")
    except Exception as e:
        logger.error(f"登录失败：{e}")
        # traceback.print_exc()
        return restful(guest_user, 401, "无效的用户名或密码")

@app.get("/bapi/logout")
async def logout(request: Request):
    '''登出接口'''
    try:
        # 删除会话
        session_id = request.cookies.get("session_id")
        response = Response(content=json.dumps({'code': 200, 'retcode': 0,'msg': '登出成功', 'data': None}, ensure_ascii=False), status_code=200, media_type='application/json; charset=UTF-8')
        response.delete_cookie("session_id")
        
        # 删除记住令牌（如果有）
        hashed_token = request.cookies.get("hashed_token")
        uid = request.cookies.get("remember_uid")
        if uid:
            redis_client.delete(f"rmb:{uid}")
        if hashed_token:
            redis_client.delete(f"rmb_uid:{hashed_token}")
        response.delete_cookie("hashed_token")
        response.delete_cookie("remember_token")
        response.delete_cookie("remember_uid")
        
        return response
    except Exception as e:
        logger.error(f"登出失败：{e}")
        # traceback.print_exc()
        return restful(guest_user, 500, f"登出失败: {str(e)}")

@app.post('/bapi/send_verify_code')
async def bapi_send_verify_code(request: Request, item: dict, user: User = Depends(get_current_user)):
    """发送验证码邮件接口"""
    # 验证邮箱格式
    recv_email = item.get('email', '')
    operation = item.get('operation', '')
    if not re.fullmatch(EMAIL_REGEX, recv_email):
        return restful(guest_user, 400, "无效的邮箱格式")
    qq_id = None
    try:
        assert recv_email.endswith('@qq.com')
        qq_id = int(recv_email.split('@')[0])
    except:
        return restful(guest_user, 400, "请使用旧版QQ邮箱注册")
    email_exist = blacklist_server.check_exist_user(qq_id) # 有可能是重置密码
    if operation == ACCOUNT_REGISTER and user.type == USER_TYPE_GUEST and email_exist:
        return restful(guest_user, 400, "该邮箱已被注册")
    # 检查发送频率 (60秒内只能发送一次)
    rest_time = redis_client.ttl(f"vcode_limit:{recv_email}")
    if rest_time != -2:
        return restful(guest_user, 429, f"请等待{rest_time}秒后再试")
    
    # 检查总发送频率
    rest_time = redis_client.ttl(f"vcode_limit:server")
    if rest_time != -2:
        return restful(guest_user, 429, f"服务器繁忙，请等待{rest_time}秒后再试")
    
    # 生成6位数字验证码
    verification_code = ''.join(random.choices('0123456789', k=6))
    redis_client.setex(f"vcode:{recv_email}", EXPIRE_TIME, verification_code) # 保存验证码到redis
    redis_client.setex(f"vcode_fail_count:{recv_email}", EXPIRE_TIME, 0)
    redis_client.setex(f"vcode_limit:{recv_email}", USER_RESEND_TIME, 1) # 限制用户请求发送频率
    redis_client.setex(f"vcode_limit:server", SERVER_RESEND_TIME, 1) # 限制服务器请求发送频率
    
    try:
        message = f"您正在<u>黑名单系统</u>注册账号或修改资料，您的验证码是: <b>{verification_code}</b>。验证码{EXPIRE_TIME//60}分钟有效，输错超过{MAX_VERIFY_FAIL_COUNT}次将失效，请勿泄露给他人。"
        if config.DEBUG_DO_NOT_SEND_EMAIL:
            logger.info(f"[config.DEBUG_DO_NOT_SEND_EMAIL] 验证码：{verification_code} ({recv_email} <- {message})")
            return restful(guest_user, 200, "验证码已发送至控制台，请注意查收", USER_RESEND_TIME)
        
        if config.smtp_email == DEFAULT_MAIL or config.smtp_auth_code == DEFAULT_AUTH_CODE:
            return restful(guest_user, 500, "请先前往/config页面配置SMTP服务器验证码邮箱信息")
        # 创建邮件对象
        msg = EmailMessage()
        msg["Subject"] = "黑名单系统 验证码"
        msg["From"] = config.smtp_email
        msg["To"] = recv_email
        
        # 使用HTML格式邮件内容
        msg.set_content(message, subtype="html")
        try:
            with smtplib.SMTP(config.smtp_server, config.smtp_port) as server:
                server.starttls()  # 启用TLS加密
                server.login(config.smtp_email, config.smtp_auth_code)
                server.send_message(msg)
        except smtplib.SMTPResponseException as e:
            logger.error(f"SMTP服务器响应异常：{e}") # 由于部分邮箱如QQ邮箱不能很好的对接smtplib，即使发送成功也会有异常
        return restful(guest_user, 200, "验证码已发送至邮箱，请注意查收", USER_RESEND_TIME)
    except Exception as e:
        traceback.print_exc()
        return restful(guest_user, 500, f"验证码发送失败: {str(e)}")
    
@app.get('/bapi/check_email_type')
async def bapi_check_email_type(request: Request, recv_email: str):
    """检查邮箱类型"""
    # 先检查，如果不是有效邮箱或qq邮箱，则拒绝注册
    if not re.fullmatch(EMAIL_REGEX, recv_email):
        return restful(guest_user, 400, "无效的邮箱格式")
    qq_id = None
    try:
        assert recv_email.endswith('@qq.com')
        qq_id = int(recv_email.split('@')[0])
    except:
        return restful(guest_user, 400, '请使用旧版QQ邮箱注册')
    try:
        type, type_name = blacklist_server.get_register_type(qq_id)
        has_password = blacklist_server.check_exist_user(qq_id)
        return restful(guest_user, 200, "邮箱类型检查成功", {'type': type, 'type_name': type_name, 'has_password': has_password})
    except Exception as e:
        return restful(guest_user, 500, f"邮箱类型检查失败: {str(e)}")
    

def verify_password(password, is_register):
    '''检查密码是否符合要求(密码长度至少8位，包含数字和字母)'''
    length = len(password)
    if is_register:
        if length < 8: # 注册必须要修改密码
            return False
    else:
        if password == '':
            return True # 如果是空，则表示不修改密码
        if length < 8:
            return False
    if not re.search(r"[0-9]+", password):
        return False
    if not re.search(r"[a-zA-Z]+", password):
        return False
    return True

@app.post('/bapi/verify')
async def bapi_verify(request: Request, item: dict, user: User = Depends(get_current_user)):
    """修改个人信息接口（需要邮箱验证码）"""
    recv_email = item.get('email', '')
    qq_id = None
    try:
        assert recv_email.endswith('@qq.com')
        qq_id = int(recv_email.split('@')[0])
        assert qq_id > 0
    except:
        return restful(user, 400, '请使用旧版QQ邮箱注册')
    is_admin = user.type == USER_TYPE_ADMIN if user.qq_id != qq_id else False # 安全起见，管理员修改自己信息需要验证码，且不允许修改自己的类型
    vcode = redis_client.get(f"vcode:{recv_email}")
    if not vcode and not is_admin:
        return restful(user, 400, "验证码错误或已失效")
    password = item.get('password', '')
    confirm_password = item.get('confirm_password', '')
    if password != confirm_password:
        return restful(user, 400, '两次输入的密码不一致')
    email_exist = blacklist_server.check_exist_user(qq_id) # 有可能是重置密码
    try:
        operation = int(item.get('operation', ''))
        operation_name = ACCOUNT_OPERATIONS[operation]
    except:
        return restful(user, 400, "无效的操作类型")
    if operation == ACCOUNT_REGISTER and email_exist and user.qq_id != qq_id and not is_admin:
        return restful(user, 403, '该邮箱已被注册')
    unique_id = None
    try:
        if operation != ACCOUNT_RESET_PASSWORD:
            unique_id = int(item.get('unique_id', ''))
    except:
        return restful(user, 400, 'bczId必须为数字')
    user_type = item.get('user_type')
    old_user_type, old_user_type_name = blacklist_server.get_register_type(qq_id)
    if blacklist_server.has_admin:
        if user_type and user_type != old_user_type and not is_admin:
            return restful(user, 403, '不能修改用户类型')
    else:
        if is_admin:
            return restful(user, 403, '第一个用户必须是管理员')
    input_code = None
    try:
        if not is_admin:
            input_code = int(item.get('code', ''))
    except:
        return restful(user, 400, '验证码必须为数字')
    if not is_admin and int(vcode) != input_code:
        if redis_client.get(f"vcode_fail_count:{recv_email}") >= MAX_VERIFY_FAIL_COUNT:
            redis_client.delete(f"vcode:{recv_email}") # 超过最大次数，删除验证码
            redis_client.delete(f"vcode_fail_count:{recv_email}")
        else:
            redis_client.incr(f"vcode_fail_count:{recv_email}")
        return restful(user, 400, "验证码错误或已失效")
    try:
        # 检查unique_id有效性
        if operation != ACCOUNT_RESET_PASSWORD and (unique_id < 1 or unique_id > 2147483647):
            return restful(user, 400, "无效的bczId")
        # 检查nickname有效性
        nickname = None
        if operation != ACCOUNT_RESET_PASSWORD:
            nickname = item.get('nickname', '')
            if nickname == '':
                return restful(user, 400, "昵称不能为空")
            nickname_user = blacklist_server.user_name_to_id.get(nickname)
            if nickname_user and nickname_user != qq_id:
                return restful(user, 400, "昵称已被占用")
            if len(nickname) > MAX_STR_LEN:
                return restful(user, 400, f'昵称过长，请控制在{MAX_STR_LEN}字以内')
        # 检查password有效性
        if not verify_password(password, operation == ACCOUNT_REGISTER):
            return restful(user, 400, "密码不符合要求")
        # 更新到数据库
        blacklist_server.update_user(qq_id, unique_id, nickname, password, user_type)
        if password:# 刷新session（仅当密码修改时）
            global jwt_secret
            jwt_secret = secrets.token_urlsafe(32)
        else: # 没有修改密码，刷新JWT
            user.session_expired = True
        # 清除remember_token
        token_hash = redis_client.get(f"rmb:{qq_id}")
        redis_client.delete(f"rmb:{qq_id}")
        redis_client.delete(f"rmb_uid:{token_hash}")
        # 删除验证码
        redis_client.delete(f"vcode:{recv_email}")
        redis_client.delete(f"vcode_fail_count:{recv_email}")
        return restful(user, 200, f"{operation_name}成功")
    except Exception as e:
        return restful(user, 500, f"{operation_name}失败: {str(e)}")
    
        

@app.post('/bapi/search')
@limiter.limit("1/second, 30/minute")
async def bapi_search(request: Request, item: dict, user: User = Depends(get_current_user)):
    """搜索黑名单接口"""
    try:
        start = time.time()
        keyword = item.get('keyword', '')
        page = item.get('page', 1)
        limit = item.get('limit', 10)
        if keyword == 'add_by_me':
            if user.type == USER_TYPE_GUEST:
                return restful(user, 403, '请先登录')
            result = blacklist_server.get_my_records(user.qq_id, page, limit)
        else:
            result = blacklist_server.search(keyword, page, limit)
        return restful(user, 200, f'{int((time.time() - start)*1000)}ms', result)
    except Exception as e:
        return restful(user, 500, f"搜索失败: {str(e)}")

@app.post('/bapi/update')
async def bapi_update(request: Request, item: dict, user: User = Depends(get_current_user)):
    """添加、修改黑名单接口"""
    if user.type == USER_TYPE_GUEST:
        return restful(user, 403, '请先登录')
    try:
        uid = int(item.get('uid', ''))
    except:
        return restful(user, 400, 'bczId必须为数字')
    last_edit_time = int(time.time())
    create_time = None
    try:
        create_time = int(item.get('create_time', ''))
        if create_time == '':
            create_time = last_edit_time
        else:
            datetime_ = datetime.datetime.fromtimestamp(create_time)
    except:
        return restful(user, 400, '创建日期无效')
    table_id = None
    try:
        table_id = int(item.get('table_id', ''))
        assert blacklist_server.table_id_to_name(table_id) is not None
    except:
        return restful(user, 400, '无效表')
    auth_info = blacklist_server.get_target_auth_info(uid, create_time)
    if auth_info != -1: # 已存在，认为是修改
        if auth_info != user.qq_id and not user.type == USER_TYPE_ADMIN:
            return restful(user, 403, '只能修改自己创建的记录')
    else: # 新增：只能新增到有权限修改的表
        try:
            assert user.type >= table_id
        except:
            return restful(user, 403, '权限不足') # 尝试添加到更高级的表（但是修改高级表中自己以前的记录是允许的）
    nickname = item.get('nickname', '')
    if len(nickname) == 0:
        return restful(user, 400, '被拉黑者昵称不能为空')
    if len(nickname) > MAX_STR_LEN:
        return restful(user, 400, f'被拉黑者昵称过长，请控制在{MAX_STR_LEN}字以内')
    try:
        date = int(item.get('date', '')) # 在前端转换为时间戳
        datetime_ = datetime.datetime.fromtimestamp(date)
    except:
        return restful(user, 400, '退班日期无效')
    try:
        reason_id_list = item.get('reasons_str', '')
        reason_name_list = blacklist_server.reason_id_to_name(reason_id_list)
        if len(reason_name_list) == 0:
            return restful(user, 400, '原因不能为空')
    except Exception as e:
        return restful(user, 400, f'原因无效: {e}')
    recorder = item.get('recorder', '')
    if len(recorder) == 0:
        return restful(user, 400, '记录者昵称不能为空')
    if len(recorder) > MAX_STR_LEN:
        return restful(user, 400, f'记录者昵称过长，请控制在{MAX_STR_LEN}字以内')
    recorder_qq_id = None
    try:
        recorder_qq_id = int(item.get('recorder_qq_id', ''))
        assert blacklist_server.check_exist_user(recorder_qq_id)
    except:
        return restful(user, 400, '无效或未注册的记录者QQ号')
    if recorder_qq_id != user.qq_id and not user.type == USER_TYPE_ADMIN:
        return restful(user, 403, '不能修改其他人的记录')
    remark = item.get('remark', '')
    if len(remark) > MAX_REMARK_LEN:
        return restful(user, 400, f'备注过长，请控制在{MAX_REMARK_LEN}字以内')
    try:
        logger.info(f"修改黑名单成功: uid={uid}, create_time={create_time}, nickname={nickname}, date={date}, reason_id_list={reason_id_list}, recorder={recorder}, recorder_qq_id={recorder_qq_id}, remark={remark}, last_edit_time={last_edit_time}, table_id={table_id}")
        blacklist_server.update_blacklist(uid, create_time, nickname, date, reason_id_list, recorder, recorder_qq_id, remark, last_edit_time, table_id, user, save_db=True)
        return restful(user, 200, '提交成功')
    except Exception as e:
        return restful(user, 400, f'失败：{e}')

@app.post('/bapi/delete')
async def bapi_delete(request: Request, item: dict, user: User = Depends(get_current_user)):
    '''删除黑名单记录接口'''
    if user.type == USER_TYPE_GUEST:
        return restful(user, 403, '请先登录')
    try:
        uid = int(item.get('uid', ''))
    except:
        return restful(user, 400, 'uid必须为数字')
    try:
        create_time = int(item.get('create_time', ''))
        datetime_ = datetime.datetime.fromtimestamp(create_time)
    except:
        return restful(user, 400, 'create_time无效')
    operator_qq_id = user.qq_id
    operator_type = user.type
    is_admin = operator_type == USER_TYPE_ADMIN
    # 检查权限
    target_qq_id = blacklist_server.get_target_auth_info(uid, create_time)
    if target_qq_id == -1:
        return restful(user, 404, '记录不存在')
    if not target_qq_id:
        return restful(user, 403, '请联系管理员以认领或修改无主记录')
    if target_qq_id != operator_qq_id and not is_admin:
        return restful(user, 403, '只能修改自己创建的记录')
    try:
        blacklist_server.delete_blacklist(uid, create_time, user)
        logger.info(f"删除黑名单成功: uid={uid}, create_time={create_time}。操作者：{user.nickname}({operator_qq_id})类型[{operator_type}]")
        return restful(user, 200, '删除成功(^ω^)')
    except Exception as e:
        return restful(user, 400, f'失败：{e}')
    
@app.get('/bapi/my_info')
async def bapi_my_info(request: Request, user: User = Depends(get_current_user)):
    '''获取当前用户信息'''
    avatar = f"https://q1.qlogo.cn/g?b=qq&nk={user.qq_id}&s=640" if config.DEBUG_AVATAR_QQ_URL and user.qq_id and user.qq_id > 0 else f'/static/img/{user.type}.jpg'
    return {
        "avatar": avatar,
        "qq_id": user.qq_id,
        "unique_id": user.unique_id,
        "permission": blacklist_server.get_permission(user.type),
        "nickname": user.nickname
    }

@app.post('/bapi/user_info')
async def bapi_user_info(request: Request, item: dict, user: User = Depends(get_current_user)):
    '''获取用户信息'''
    try:
        qq_id = int(item.get('qq_id', ''))
        # assert blacklist_server.check_exist_user(qq_id) # 有可能是预注册的用户
    except:
        return restful(user, 400, '无效或未注册的QQ号')
    try:
        user_info = blacklist_server.get_user(qq_id)
        if user_info:
            return restful(user, 200, '获取用户信息成功', {
                'unique_id': user_info.unique_id,
                'permission': blacklist_server.get_permission(user_info.type),
                'nickname': user_info.nickname,
            })
        else:
            return restful(user, 400, '用户信息为空', user_info)
    except Exception as e:
        return restful(user, 400, f'获取用户信息失败：{e}')

@app.get('/bapi/dicts')
async def bapi_reasons(request: Request):
    '''获取原因、表、操作类型列表(id->name)'''
    try:
        reasons = blacklist_server.get_dicts()
        return restful(guest_user, 200, '获取配置列表成功', reasons)
    except Exception as e:
        return restful(guest_user, 400, f'获取配置列表失败：{e}')

@app.get('/config')
async def config_page(request: Request):
    '''配置页面'''
    return templates.TemplateResponse('config.html', {'request': request})

@app.get('/bapi/config')
async def bapi_config(request: Request, user: User = Depends(get_current_user)):
    '''获取配置信息'''
    if user.type != USER_TYPE_ADMIN:
        return restful(user, 403, '权限不足')
    try:
        return restful(user, 200, '获取配置信息成功', config.config)
    except Exception as e:
        return restful(user, 400, f'获取配置信息失败：{e}')

@app.post('/bapi/update_config')
async def bapi_update_config(request: Request, item: dict, user: User = Depends(get_current_user)):
    '''更新配置信息'''
    if user.type != USER_TYPE_ADMIN:
        return restful(user, 403, '权限不足')
    try:
        config.update_config(item)
        return restful(user, 200, '更新配置信息成功')
    except Exception as e:
        return restful(user, 400, f'更新配置信息失败：{e}')

@app.post('/bapi/latest_log')
async def bapi_latest_log(request: Request, item: dict, user: User = Depends(get_current_user)):
    '''获取最新日志'''
    # 非管理员展示最近10条日志
    try:
        page = int(item['page'])
        limit = int(item['limit'])
        result = []
        page_max = 1
        max_tot = 20 if user.type != USER_TYPE_ADMIN else None
        return restful(user, 200, '获取日志成功', blacklist_server.get_latest_logs(limit, page, max_tot))
    except Exception as e:
        return restful(user, 400, f'获取日志失败：{e}')


# 下列是手动调用方法

@app.get('/submit')
async def submit_page(request: Request):
    '''提交页面'''
    return templates.TemplateResponse('submit.html', {'request': request})

@app.post('/oapi/bulk')
async def bapi_bulk_add_user(request: Request, item: dict, user: User = Depends(get_current_user)):
    '''批量添加用户'''
    if user.type != USER_TYPE_ADMIN:
        return restful(user, 403, '权限不足')
    try:
        user_list = item.get('qq', '').replace('\n','').split(',') # qq,nickname,qq,nickname...
        for i in range(0, len(user_list), 2):
            if not user_list[i] or not user_list[i+1]:
                continue
            qq_id = int(user_list[i])
            nickname = user_list[i+1]
            blacklist_server.update_user(qq_id, 1, nickname, None, USER_TYPE_KING)
        return restful(user, 200, '批量添加用户成功')
    except Exception as e:
        return restful(user, 400, f'批量添加用户失败：{e}')
    
@app.get('/oapi/count')
async def bapi_count(request: Request, user: User = Depends(get_current_user)):
    '''获取记录过黑名单的用户，按记录的多少排序'''
    if user.type != USER_TYPE_ADMIN:
        return restful(user, 403, '权限不足')
    try:
        count_list = blacklist_server.get_count_list()
        return restful(user, 200, '获取记录数量成功', count_list)
    except Exception as e:
        return restful(user, 400, f'获取记录数量失败：{e}')

@app.get('/oapi/repair')
async def bapi_repair_blacklist(request: Request, user: User = Depends(get_current_user)):
    '''修复黑名单'''
    if user.type != USER_TYPE_ADMIN:
        return restful(user, 403, '权限不足')
    try:
        blacklist_server.repair_blacklist()
        return restful(user, 200, '修复黑名单成功')
    except Exception as e:
        return restful(user, 400, f'修复黑名单失败：{e}')

@app.get('/oapi/download')
async def blacklist(request: Request, user: User = Depends(get_current_user)):
    '''下载黑名单数据库（用于备份）'''
    if user.type != USER_TYPE_ADMIN:
        return restful(user, 403, '权限不足')
    try:
        # 将数据库文件返回给客户端
        with open(config.blacklist_db_path, 'rb') as f:
            content = f.read()
        response = StreamingResponse(content, media_type='application/octet-stream')
        response.headers['Content-Disposition'] = 'attachment; filename="blacklist.db"'
        return response
    except Exception as e:
        return restful(user, 400, f'{e}')
    
@app.post('/oapi/upload')
async def bapi_upload(request: Request, user: User = Depends(get_current_user)):
    '''上传黑名单数据库（用于恢复）'''
    if user.type != USER_TYPE_ADMIN:
        return restful(user, 403, '权限不足')
    try:
        # 接收上传的文件
        form = await request.form()
        file = form['file']
        # 保存文件
        with open(config.blacklist_db_path, 'wb') as f:
            f.write(file.file.read())
        # 重载
        del blacklist_server
        blacklist_server = blacklist_server_class(config.blacklist_db_path)
        blacklist_server.prepare()
        redis_client.flushall()
        return restful(user, 200, '上传成功，数据库已重载')
    except Exception as e:
        return restful(user, 400, f'{e}')

def restful(user: User, code: int, msg: str = '', data: dict = {}, remember_me: bool = False) -> Response:
    '''以RESTful的方式进行返回响应'''
    retcode = 1
    if code == 200:
        retcode = 0
    return refresh_session(user, Response(
        content=json.dumps({'code': code,
            'retcode': retcode,
            'msg': msg,
            'data': data
    }, ensure_ascii=False), status_code=code, media_type='application/json; charset=UTF-8'), remember_me)


if __name__ == '__main__':
    for name in logging.Logger.manager.loggerDict.keys():
        if 'httpx' in name: # 输出http2多路请求的日志，如需要requests的日志，则加入'urllib3' in name
            tlogger = logging.getLogger(name)
            tlogger.setLevel(logging.DEBUG)

    logger.info('BCZ-Blacklist 启动中...')
    uvicorn.run(app, host=config.host, port=config.port)
