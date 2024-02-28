from flask import g, request
from apiflask import APIFlask, Schema
from apiflask.fields import String
from apiflask.views import MethodView
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, \
    get_jwt_identity
from datetime import timedelta

# 初始化 Flask app 可改成工廠模式
app = APIFlask(__name__)

# Flask Config 設定，可改成 config.py 處理
app.config['SECRET_KEY'] = 'kevinExampleProj'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(hours=20)

# 改另寫 extends 處理
# 設定跨域 CORS，可改成讀取設定檔 Frontend 的網址
CORS(app, resources={r"/*": {"origins": ["http://localhost:4200", "http://127.0.0.1:4200"]}})
# 初始化 JWT
auth_token = JWTManager(app)
# 初始化 HTTPBasicAuth
auth_basic = HTTPBasicAuth()

# 使用者列表，可改成讀取資料庫
users = [
    {'id': 1, 'username': 'admin', 'password': 'admin'},
    {'id': 2, 'username': 'user01', 'password': 'passw0rd'},
    {'id': 3, 'username': 'user02', 'password': 'passw0rd'}
]


# Schema 驗證
class LoginInSchema(Schema):
    username = String(required=True)
    password = String(required=True)


# HTTP Basic 驗證
@auth_basic.verify_password
def verify_password(username, password):
    user = [user for user in users if user['username'] == username]
    if user and user[0]['password'] == password:
        g.user = user[0]
        return True
    return False


# 可包裝進藍圖處理
@app.get('/', strict_slashes=False)
@app.get('/apis', strict_slashes=False)
def index():
    return {'message': 'Hello, APIFlask!'}


class TokenApi(MethodView):
    # 通用裝飾器
    # decorators = [auth_basic.login_required]

    @auth_basic.login_required
    def get(self):
        """
        使用 HTTP Basic 驗證取得 Token
        """
        access_token = create_access_token(identity=g.user)
        refresh_token = create_refresh_token(identity=g.user)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }

    @app.input(LoginInSchema, location='json')
    def post(self, **kwargs):
        """
        使用 HTTP Post 驗證取得 Token
        :param kwargs:
        :return:
        """
        # raw_data = request.json 不使用 @app.input 裝飾器
        raw_data = kwargs.get('json_data', {})
        username = raw_data.get('username', '')
        password = raw_data.get('password', '')

        if not verify_password(username, password):
            return {'message': 'Unauthorized Access'}, 401

        access_token = create_access_token(identity=g.user)
        refresh_token = create_refresh_token(identity=g.user)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }


    @jwt_required(refresh=True)
    def put(self, **kwargs):
        """
        更新 Access Token
        """
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        raw_token = request.headers['Authorization'].split(' ')[1]
        return {'access_token': access_token, 'refresh_token': raw_token}


# 將 ClassView 綁到 url
app.add_url_rule('/apis/auth/token', view_func=TokenApi.as_view('token_api'))

