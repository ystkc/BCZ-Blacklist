
import datetime
import json
import bcrypt
from src.blacklist_utils import blacklist_server_class
from fastapi import FastAPI, Request, Response
from fastapi import Depends, HTTPException, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from fastapi.security import OAuth2PasswordRequestForm
import logging
import secrets


LOGGING_LEVEL = logging.INFO
IS_HTTPS = False # 本地开发环境下，设置为False，以便支持http请求


logging.basicConfig(
    format='%(asctime)s [%(name)s][%(levelname)s] %(message)s',
    level=LOGGING_LEVEL
)
app = FastAPI()
limiter = Limiter(key_func=lambda: 'ip', default_limits=["300 per minute"])
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)
blacklist_server = blacklist_server_class()
logger = logging.getLogger(__name__)
try:
    blacklist_server.prepare()
except Exception as e:
    logger.error(f"初始化黑名单服务器失败：{e}")

# 以下是黑名单部分
sessions = {} # {"session_id": {"username": "xxx", "expires": "xxx"}}
def create_session(username: str, response: Response, remember_me: bool = False):
    '''创建session'''
    session_id = secrets.token_urlsafe(32)
    expires = (datetime.datetime.now() + datetime.timedelta(days=14)).timestamp() if remember_me else None
    sessions[session_id] = {"username": username, "expires": expires, 'remember_token': []}
    response.set_cookie(key='session_id', value=session_id, httponly=True, secure=IS_HTTPS, samesite='lax', max_age=3600*24*14 if remember_me else None, expires=expires) # 默认本地端没有https，所以secure=False
    if remember_me:
        remember_token = secrets.token_urlsafe(64)
        hashed_token = bcrypt.hashpw(remember_token.encode('utf-8'), bcrypt.gensalt())
        sessions[session_id]['remember_token'].append(hashed_token)
        response.set_cookie(key='remember_token', value=hashed_token, httponly=False, secure=IS_HTTPS, samesite='lax', max_age=3600*24*14) # 设置httponly=False，可以用JavaScript读取
    return session_id

def get_current_user(request: Request) -> dict:
    """获取当前用户"""
    # 首先尝试从会话Cookie获取
    session_id = request.cookies.get("session_id")
    if session_id and session_id in sessions:
        session = sessions[session_id]
        if session['expires'] > datetime.datetime.now().timestamp():
            user_data = blacklist_server.get_user(session['username'])
            if user_data:
                return user_data
    
    # 如果会话无效，尝试使用记住令牌重新认证
    remember_token = request.cookies.get("remember_token")
    if remember_token:
        username = request.cookies.get("remember_username")
        if username and False:
            user = fake_users_db[username]
            # 验证令牌
            for token_hash in user.remember_tokens:
                # 比较哈希后的令牌
                if token_hash == hash_remember_token(remember_token):
                    # 创建新会话
                    create_session(username, Response(), remember_me=True)
                    return user
    
    # 如果没有有效会话或记住令牌
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "Bearer"},
    )

# === API端点 ===
# @app.post("/login")
# async def login(
#     form_data: OAuth2PasswordRequestForm = Depends(),
#     remember_me: bool = False,  # 来自前端表单的"记住我"选项
#     response: Response = None
# ):
#     # 查找用户
#     user = fake_users_db.get(form_data.username)
#     if not user:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
    
#     # 验证密码
#     if not verify_password(form_data.password, user.password_hash):
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
    
#     # 创建会话
#     create_session(user.username, response, remember_me)
    
#     return {"message": "Login successful"}

# @app.post("/logout")
# async def logout(request: Request, response: Response):
#     # 删除会话
#     session_id = request.cookies.get("session_id")
#     if session_id in sessions:
#         del sessions[session_id]
    
#     # 删除会话Cookie
#     response.delete_cookie("session_id")
    
#     # 删除记住令牌（如果有）
#     remember_token = request.cookies.get("remember_token")
#     username = request.cookies.get("remember_username")
#     if remember_token and username:
#         # 从用户记录中移除令牌
#         if username in fake_users_db:
#             user = fake_users_db[username]
#             # 删除所有匹配的令牌
#             token_hash = hash_remember_token(remember_token)
#             user.remember_tokens = [t for t in user.remember_tokens if t != token_hash]
        
#         # 删除记住令牌Cookie
#         response.delete_cookie("remember_token")
    
#     return {"message": "Logout successful"}

# @app.get("/protected-data")
# async def protected_data(user: dict = Depends(get_current_user)):
#     return {
#         "message": f"Hello {user.username}!",
#         "protected_info": "This is sensitive data"
#     }

# @app.get("/user-info")
# async def user_info(request: Request):
#     """仅使用记住令牌验证（适用于AJAX请求）"""
#     remember_token = request.cookies.get("remember_token")
#     username = request.cookies.get("remember_username")
    
#     if remember_token and username and username in fake_users_db:
#         user = fake_users_db[username]
#         for token_hash in user.remember_tokens:
#             if token_hash == hash_remember_token(remember_token):
#                 return {"username": username, "status": "remembered"}
    
#     return {"status": "guest"}


@app.get('/bapi/send_verify_code')
async def bapi_send_verify_code(request: Request, email: str):
    """发送验证码邮件接口"""
    code, msg, data = blacklist_server.send_verify_code(email)
    return restful(code, msg, data)
    
@app.post('/bapi/verify')
async def bapi_verify(request: Request, item: dict):
    """验证验证码接口"""
    email = item.get('email', '')
    unique_id = item.get('unique_id', '')
    nickname = item.get('nickname', '')
    password = item.get('password', '')
    code = item.get('code', '')
    blacklist_server.verify(email, password, code)

@app.post('/bapi/search')
async def bapi_search(request: Request, item: dict):
    """搜索黑名单接口"""
    keyword = item.get('keyword', '')
    page = item.get('page', 1)
    limit = item.get('limit', 10)
    data = blacklist_server.search(keyword, page, limit)
    return restful(200, '搜索成功', data)

@app.post('/bapi/add')
async def bapi_add(request: Request, item: dict):
    """添加黑名单接口"""
    uid = item.get('uid', '')
    create_time = datetime.datetime.now()
    nickname = item.get('nickname', '')
    reason = item.get('reason', '')
    recorder = item.get('recorder', '')
    recorder_qq_id


@app.get('/blacklist')
async def blacklist(request: Request):
    '''导出黑名单'''
    try:
        blacklist_server.export_black_list()
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

