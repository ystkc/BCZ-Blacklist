
import traceback
import datetime
from email.message import EmailMessage
import json
import os
import random
import re
import smtplib
import bcrypt
import redis
import uvicorn
from src.blacklist_utils import blacklist_server_class, User, guest_user, USER_TYPE_GUEST, USER_TYPE_ADMIN
from fastapi import FastAPI, Request, Response
from fastapi import Depends, HTTPException, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.security import OAuth2PasswordRequestForm
import logging
from pydantic import BaseModel
import secrets


LOGGING_LEVEL = logging.INFO
IS_HTTPS = False # 本地开发环境下，设置为False，以便支持http请求
SESSION_EXPIRE_TIME = 300 # 会话过期时间，单位秒
REMEMBER_ME_TIME = 3600*24*14 # 记住我选项的有效期，单位秒
DEFAULT_LIMITS = ["3/second", "30/minute", "300/hour"] # 默认访问速率限制
MAX_STR_LEN = 31 # 黑名单每个字符串的最大长度
MAX_REMARK_LEN = 255 # 黑名单备注的最大长度


USER_RESEND_TIME = 60 # 同一用户连续两次发送验证码的最短间隔时间
SERVER_RESEND_TIME = 20 # 服务器连续两次发送验证码的最短间隔时间
EXPIRE_TIME = 600 # 验证码有效期（秒）
MAX_VERIFY_FAIL_COUNT = 3 # 最大验证码错误次数

DEFAULT_MAIL = "[necessary]your_email@qq.com"
DEFAULT_AUTH_CODE = "[necessary]your_authorization_code"

EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")


class Config():
    BLACKLIST_CONFIG_PATH = './blacklist.json' # 黑名单配置路径（现在仅储存授权码）
    def __init__(self):
        if not os.path.exists(self.BLACKLIST_CONFIG_PATH):
            self.config = {}
        else:
            with open(self.BLACKLIST_CONFIG_PATH, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        self.update_config(self.config)

    def update_config(self, config: dict):
        self.blacklist_xlsx_path = config.get('blacklist_xlsx_path', './blacklist.xlsx') # 黑名单excel文件路径（只读）空置或文件无效时则跳过导入
        self.blacklist_db_path = config.get('blacklist_db_path', './blacklist.db') # 黑名单数据库路径（读&写）
        self.blacklist_assets = config.get('blacklist_assets', './assets/black_list.bin') # 黑名单数据路径（仅导出）
        self.smtp_server = config.get('smtp_server', 'smtp.qq.com') # SMTP服务器地址
        self.smtp_port = config.get('smtp_port', 587) # SMTP服务器端口
        self.smtp_email = config.get('smtp_email', DEFAULT_MAIL) # SMTP服务器用户名
        self.smtp_auth_code = config.get('smtp_auth_code', DEFAULT_AUTH_CODE) # SMTP服务器密码
        self.host = config.get('host', '127.0.0.1') # 服务器监听地址
        self.port = config.get('port', 8870) # 服务器监听端口
        new_config = {
            'blacklist_xlsx_path': self.blacklist_xlsx_path,
            'blacklist_db_path': self.blacklist_db_path,
            'blacklist_assets': self.blacklist_assets,
           'smtp_server': self.smtp_server,
           'smtp_port': self.smtp_port,
           'smtp_email': self.smtp_email,
           'smtp_auth_code': self.smtp_auth_code,
            'host': self.host,
            'port': self.port
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


logging.basicConfig(
    format='%(asctime)s [%(name)s][%(levelname)s] %(message)s',
    level=LOGGING_LEVEL
)
app = FastAPI()
limiter = Limiter(key_func=get_remote_address, default_limits=DEFAULT_LIMITS)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

redis_pool = redis.ConnectionPool(host='localhost', port=6379, db=0, decode_responses=True)
redis_client = redis.Redis(connection_pool=redis_pool)
logger.info("redis连接成功")
blacklist_server = blacklist_server_class(config.blacklist_db_path)
try:
    blacklist_server.prepare(config.blacklist_xlsx_path)
except Exception as e:
    logger.error(f"初始化黑名单服务器失败：{e}")
    traceback.print_exc()

@app.post('/send_verify_code')
async def send_verify_code(request: Request, item: VerifyCodeRequest):
    """发送验证码邮件接口"""
    code, msg, data = blacklist_server.send_verify_code(item.recv_email)
    return restful(code, msg, data)

def create_session(uid: str, response: Response, remember_me: bool = False):
    '''创建session'''
    session_id = secrets.token_urlsafe(32)
    expires = (datetime.datetime.now().timestamp() + SESSION_EXPIRE_TIME)
    redis_client.setex(f"session:{session_id}", SESSION_EXPIRE_TIME, uid)
    response.set_cookie(key='session_id', value=session_id, httponly=True, secure=IS_HTTPS, samesite='lax', max_age=None) # 默认本地端没有https，所以secure=False
    if remember_me:
        hashed_token = blacklist_server.create_remember_token(uid, REMEMBER_ME_TIME)
        response.set_cookie(key='remember_token', value=hashed_token, httponly=True, secure=IS_HTTPS, samesite='lax', max_age=REMEMBER_ME_TIME) # 设置httponly=False，可以用JavaScript读取
        response.set_cookie(key='remember_uid', value=uid, httponly=True, secure=IS_HTTPS, samesite='lax', max_age=REMEMBER_ME_TIME) # 设置httponly=False，可以用JavaScript读取
    return session_id

def get_current_user(request: Request, response: Response) -> dict:
    """获取当前用户"""
    # 首先尝试从会话Cookie获取
    session_id = request.cookies.get("session_id")
    uid = redis_client.get(f"session:{session_id}")
    if uid:
        user_data = blacklist_server.get_user(uid)
        if user_data:
            return user_data
    
    # 如果会话无效，尝试使用记住令牌重新认证
    uid = request.cookies.get("remember_uid")
    if blacklist_server.verify_remember_token(uid, request.cookies.get("remember_token")):
        create_session(uid, response, False)
        user_data = blacklist_server.get_user(uid)
        if user_data:
            return user_data
        
    # 如果没有有效会话或记住令牌：访客模式
    return guest_user

# === API端点 ===
@app.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    remember_me: bool = False,  # 来自前端表单的"记住我"选项
    response: Response = None
):
    '''登录接口'''
    try:
        uid = form_data.username
        if blacklist_server.login(uid, form_data.password):
            create_session(uid, response, remember_me)
            return restful(200, "登录成功")
        return restful(401, "无效的用户名或密码")
    except Exception as e:
        return restful(401, "无效的用户名或密码")

@app.post("/logout")
async def logout(request: Request, response: Response):
    '''登出接口'''
    # 删除会话
    session_id = request.cookies.get("session_id")
    redis_client.delete(f"session:{session_id}")
    response.delete_cookie("session_id")
    
    # 删除记住令牌（如果有）
    remember_token = request.cookies.get("remember_token")
    uid = request.cookies.get("remember_uid")
    if remember_token and uid:
        redis_client.delete(f"rmb:{uid}")
        response.delete_cookie("remember_token")
    
    return restful(200, "登出成功")

@app.get('/bapi/send_verify_code')
async def bapi_send_verify_code(request: Request, recv_email: str):
    """发送验证码邮件接口"""
    # 验证邮箱格式
    if not re.fullmatch(EMAIL_REGEX, recv_email):
        return restful(400, "无效的邮箱格式")
    if not recv_email.endswith('@qq.com') or not recv_email.split('@')[0].isdigit() :
        return restful(400, "请使用旧版QQ邮箱注册")
    
    # 检查发送频率 (60秒内只能发送一次)
    rest_time = redis_client.ttl(f"vcode_limit:{recv_email}")
    if rest_time != -2:
        return restful(429, f"请等待{rest_time}秒后再试")
    
    # 检查总发送频率
    rest_time = redis_client.ttl(f"vcode_limit:server")
    if rest_time != -2:
        return restful(429, f"服务器繁忙，请等待{rest_time}秒后再试")
    
    # 生成6位数字验证码
    verification_code = ''.join(random.choices('0123456789', k=6))
    redis_client.setex(f"vcode:{recv_email}", EXPIRE_TIME, verification_code) # 保存验证码到redis
    redis_client.setex(f"vcode_fail_count:{recv_email}", EXPIRE_TIME, 0)
    redis_client.setex(f"vcode_limit:{recv_email}", USER_RESEND_TIME, 1) # 限制用户请求发送频率
    redis_client.setex(f"vcode_limit:server", SERVER_RESEND_TIME, 1) # 限制服务器请求发送频率
    
    try:
        if config.smtp_email == DEFAULT_MAIL or config.smtp_auth_code == DEFAULT_AUTH_CODE:
            raise Exception("请先配置SMTP服务器验证码邮箱信息")
        message = f"您正在<u>黑名单系统</u>注册账号或修改资料，您的验证码是: <b>{verification_code}</b>。验证码{EXPIRE_TIME//60}分钟有效，输错超过{MAX_VERIFY_FAIL_COUNT}次将失效，请勿泄露给他人。"
        # 创建邮件对象
        msg = EmailMessage()
        msg["Subject"] = "黑名单系统 验证码"
        msg["From"] = config.smtp_email
        msg["To"] = recv_email
        
        # 使用HTML格式邮件内容
        msg.set_content(message, subtype="html")
        with smtplib.SMTP(config.smtp_server, config.smtp_port) as server:
            server.starttls()  # 启用TLS加密
            server.login(config.smtp_email, config.smtp_auth_code)
            server.send_message(msg)
        
        return restful(200, "验证码已发送至邮箱，请注意查收")
    except Exception as e:
        return restful(500, f"验证码发送失败: {str(e)}")
    
@app.post('/bapi/verify')
async def bapi_verify(request: Request, item: dict, user: User = Depends(get_current_user)):
    """修改个人信息接口（需要邮箱验证码）"""
    recv_email = item.get('email', '')
    try:
        qq_id = int(recv_email.split('@')[0])
    except:
        return restful(400, '请使用旧版QQ邮箱注册')
    is_admin = user.type == USER_TYPE_ADMIN if user.qq_id != qq_id else False # 安全起见，管理员修改自己信息需要验证码，且不允许修改自己的类型
    vcode = redis_client.get(f"vcode:{recv_email}")
    if not vcode and not is_admin:
        return restful(400, "验证码错误或已失效")
    if user.qq_id != qq_id and not is_admin:
        return restful(403, '不能修改其他用户信息')
    try:
        unique_id = int(item.get('unique_id', ''))
    except:
        return restful(400, 'unique_id必须为数字')
    user_type = item.get('user_type')
    if user_type and not is_admin:
        return restful(403, '不能修改用户类型')
    nickname = item.get('nickname', '')
    password = item.get('password', '')
    input_code = item.get('code', '')
    if vcode.decode('utf-8') != input_code and not is_admin:
        if redis_client.get(f"vcode_fail_count:{recv_email}") >= MAX_VERIFY_FAIL_COUNT:
            redis_client.delete(f"vcode:{recv_email}") # 超过最大次数，删除验证码
            redis_client.delete(f"vcode_fail_count:{recv_email}")
        else:
            redis_client.incr(f"vcode_fail_count:{recv_email}")
        return restful(400, "验证码错误或已失效")
    try:
        # 检查是否是qq邮箱，否则拒绝注册
        qq_id = recv_email.split('@')[0]
        if not recv_email.endswith('@qq.com') or not qq_id.isdigit():
            return restful(400, "请使用旧版QQ邮箱注册")
        # 检查unique_id有效性
        if not unique_id.isdigit() or unique_id > 2147483647:
            return restful(400, "无效的unique_id")
        # 检查nickname有效性
        if len(nickname) > MAX_STR_LEN:
            return restful(400, f'昵称过长，请控制在{MAX_STR_LEN}字以内')
        # 更新到数据库
        blacklist_server.update_user(qq_id, unique_id, nickname, password)
        # 清除remember_token
        redis_client.delete(f"rmb:{qq_id}")
        # 删除验证码
        redis_client.delete(f"vcode:{recv_email}")
        redis_client.delete(f"vcode_fail_count:{recv_email}")
        return restful(200, "已注册，资料已更新")
    except Exception as e:
        return restful(500, f"失败: {str(e)}")
        

@app.post('/bapi/search')
async def bapi_search(request: Request, item: dict):
    """搜索黑名单接口"""
    keyword = item.get('keyword', '')
    page = item.get('page', 1)
    limit = item.get('limit', 10)
    data = blacklist_server.search(keyword, page, limit)
    return restful(200, '搜索成功', data)

@app.post('/bapi/update')
async def bapi_update(request: Request, item: dict, user: User = Depends(get_current_user)):
    """添加、修改黑名单接口"""
    # 检查权限
    try:
        table = int(item.get('table', ''))
        assert user.type >= table
    except:
        return restful(403, '权限不足')
    try:
        uid = int(item.get('uid', ''))
    except:
        return restful(400, 'uid必须为数字')
    create_time = datetime.datetime.now()
    is_add = item.get('is_add', False) # 是否是新增记录
    if is_add and blacklist_server.check_exist(uid, create_time):
        return restful(400, '该记录已存在，请确认没有重复添加')
    nickname = item.get('nickname', '')
    if len(nickname) > MAX_STR_LEN:
        return restful(400, f'被拉黑者昵称过长，请控制在{MAX_STR_LEN}字以内')
    try:
        date = int(item.get('date', '')) # 在前端转换为时间戳
        datetime_ = datetime.datetime.fromtimestamp(date)
    except:
        return restful(400, '日期无效')
    try:
        reason_id_list = blacklist_server.reason_name_to_id(item.get('reason', ''))
    except:
        return restful(400, '原因无效')
    recorder = item.get('recorder', '')
    if len(recorder) > MAX_STR_LEN:
        return restful(400, f'记录者昵称过长，请控制在{MAX_STR_LEN}字以内')
    recorder_qq_id = user.qq_id
    remark = item.get('remark', '')
    if len(remark) > MAX_REMARK_LEN:
        return restful(400, f'备注过长，请控制在{MAX_REMARK_LEN}字以内')
    last_edit_time = datetime.datetime.now()
    try:
        blacklist_server.update_blacklist(uid, create_time, nickname, date, reason_id_list, recorder, recorder_qq_id, remark, last_edit_time, table, save_db=True)
        if is_add:
            logger.info(f"添加黑名单成功: uid={uid}, create_time={create_time}, nickname={nickname}, date={date}, reason_id_list={reason_id_list}, recorder={recorder}, recorder_qq_id={recorder_qq_id}, remark={remark}, last_edit_time={last_edit_time}, table={table}")
            return restful(200, '添加成功')
        else:
            logger.info(f"修改黑名单成功: uid={uid}, create_time={create_time}, nickname={nickname}, date={date}, reason_id_list={reason_id_list}, recorder={recorder}, recorder_qq_id={recorder_qq_id}, remark={remark}, last_edit_time={last_edit_time}, table={table}")
            return restful(200, '修改成功')
    except Exception as e:
        return restful(400, f'失败：{e}')

@app.post('/bapi/delete')
async def bapi_delete(request: Request, item: dict, user: User = Depends(get_current_user)):
    '''删除黑名单记录接口'''
    try:
        uid = int(item.get('uid', ''))
    except:
        return restful(400, 'uid必须为数字')
    try:
        create_time = datetime.datetime.fromtimestamp(int(item.get('create_time', '')))
    except:
        return restful(400, 'create_time无效')
    operator_qq_id = user.qq_id
    operator_type = user.type
    is_admin = operator_type == USER_TYPE_ADMIN
    # 检查权限
    target_qq_id = blacklist_server.get_target_auth_info(uid, create_time)
    if not target_qq_id:
        return restful(403, '请联系管理员以认领或修改无主记录')
    if target_qq_id != operator_qq_id and not is_admin:
        return restful(403, '只能修改自己创建的记录')
    try:
        blacklist_server.delete_blacklist(uid, create_time, operator_qq_id, operator_type)
        logger.info(f"删除黑名单成功: uid={uid}, create_time={create_time}。操作者：{user.nickname}({operator_qq_id})类型[{operator_type}]")
        return restful(200, '删除成功(^ω^)')
    except Exception as e:
        return restful(400, f'失败：{e}')

@app.get('/bapi/my_records')
async def bapi_my_records(request: Request, user: User = Depends(get_current_user)):
    '''获取当前用户添加的黑名单记录'''
    try:
        blacklist_server.get_my_records(user.unique_id)
        return restful(200, '获取记录成功(^ω^)')
    except Exception as e:
        return restful(400, f'获取记录失败：{e}')
    
@app.get('/bapi/my_info')
async def bapi_my_info(request: Request, user: User = Depends(get_current_user)):
    '''获取当前用户信息'''
    return {
        "qq_id": user.qq_id,
        "unique_id": user.unique_id,
        "permission": blacklist_server.get_permission(user.type),
        "nickname": user.nickname
    }

@app.get('/bapi/reasons')
async def bapi_reasons(request: Request):
    '''获取原因列表(id->name)'''
    try:
        reasons = blacklist_server.get_reasons()
        return restful(200, '获取原因列表成功', reasons)
    except Exception as e:
        return restful(400, f'获取原因列表失败：{e}')

@app.get('/bapi/config')
async def bapi_config(request: Request, user: User = Depends(get_current_user)):
    '''获取配置信息'''
    if user.type != USER_TYPE_ADMIN:
        return restful(403, '权限不足')
    try:
        return restful(200, '获取配置信息成功', config.config)
    except Exception as e:
        return restful(400, f'获取配置信息失败：{e}')

@app.get('/bapi/update_config')
async def bapi_update_config(request: Request, item: dict, user: User = Depends(get_current_user)):
    '''更新配置信息'''
    if user.type != USER_TYPE_ADMIN:
        return restful(403, '权限不足')
    try:
        config.update_config(item)
        return restful(200, '更新配置信息成功')
    except Exception as e:
        return restful(400, f'更新配置信息失败：{e}')

@app.get('/bapi/blacklist')
async def blacklist(request: Request, user: User = Depends(get_current_user)):
    '''导出黑名单'''
    if user.type != USER_TYPE_ADMIN:
        return restful(403, '权限不足')
    try:
        blacklist_server.export_black_list_to_bin(config.blacklist_assets)
        return restful(200, '导出黑名单成功')
    except Exception as e:
        return restful(400, f'{e}')

def restful(code: int, msg: str = '', data: dict = {}) -> Response:
    '''以RESTful的方式进行返回响应'''
    retcode = 1
    if code == 200:
        retcode = 0
    return Response(
        content=json.dumps({'code': code,
            'retcode': retcode,
            'msg': msg,
            'data': data
    }, ensure_ascii=False), status_code=code, media_type='application/json; charset=UTF-8')


if __name__ == '__main__':
    for name in logging.Logger.manager.loggerDict.keys():
        if 'httpx' in name: # 输出http2多路请求的日志，如需要requests的日志，则加入'urllib3' in name
            tlogger = logging.getLogger(name)
            tlogger.setLevel(logging.DEBUG)

    logger.info('BCZ-Blacklist 启动中...')
    uvicorn.run(app, host=config.host, port=config.port)
