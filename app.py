from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient('localhost', 27017)  # mongoDB는 27017 포트로 돌아갑니다.
db = client.project  # 'dbsparta'라는 이름의 db를 만듭니다.

# JWT 토큰을 만들 때 필요한 비밀문자열
# 이 문자열은 서버만 알고있기 때문에, 내 서버에서만 토큰을 인코딩(=만들기)/디코딩(=풀기) 할 수 있습니다.
SECRET_KEY = 'sparta'

# JWT 패키지를 사용합니다. (설치해야할 패키지 이름: PyJWT)
import jwt

# datetime- 토큰시간 만료
import datetime

# 비밀번호 암호화로 저장
import hashlib


## HTML을 주는 부분
@app.route('/')
def home():
    return render_template('next.html')


@app.route('/Login')
def Login():
    return render_template('Login.html')


# @app.route('/Next')
# def Next():
#     return render_template('next.html')


# 회원가입 API

@app.route('/api/signup', methods=['POST'])
def make_sign():
    id_receive = request.form['ID_give']
    password_receive = request.form['Password_give']
    nickname_receive = request.form['Nickname_give']

    pw_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()

    info = {
        'ID': id_receive,
        'Password': pw_hash,
        'Nickname': nickname_receive,
    }

    db.infos.insert_one(info)

    return jsonify({'result': 'success', 'msg': '회원가입이 완료되었습니다'})


# 아이디 중복확인
@app.route('/api/overlap', methods=['POST'])
def overlap_check():
    id_receive = request.form['ID_give']

    overlap = db.infos.find({'ID': id_receive}).count()

    if overlap == 0:
        return jsonify({'result': 'success','msg': '사용가능한 아이디입니다.'})
    else:
        return jsonify({'result': 'fail', 'msg': '중복된 아이디입니다.'})


# 로그인 API

@app.route('/api/Login', methods=['POST'])
def api_login():
    id_receive = request.form['ID_give']
    password_receive = request.form['Password_give']
    # print(password_receive)
    pw_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    # print(pw_hash)
    # id, 암호화된 pw을 가지고 해당 유저를 찾습니다.
    check = db.infos.find_one({'ID': id_receive, 'Password': pw_hash})

    # 찾으면 JWT 토큰을 만들어 발급합니다.
    if check is not None:
        # JWT 토큰에는, payload와 시크릿키가 필요
        # 시크릿키가 있어야 토큰을 디코딩(=풀기) 해서 payload 값을 볼 수 있음
        # id와 exp를 담고 WT 토큰을 풀면 유저ID 값을 알 수 있습니다.
        # exp에는 만료시간. 만료시간이 지나면, 시크릿키로 토큰을 풀 때 만료되었다고 에러가 남
        payload = {
            'ID': id_receive,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=600)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode('utf-8')

        # token을 줍니다.
        return jsonify({'result': 'success', 'token': token})
    # 찾지 못하면
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})


# [유저 정보 확인 API]
# 로그인된 유저만 call 할 수 있는 API.
@app.route('/api/Next', methods=['GET'])
def api_valid():
    # header에 저장해서 넘겨주어 토큰을 주고 받음
    token_receive = request.headers['token_give']

    try:
        # token을 시크릿키로 디코딩
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        print(payload)
        # payload 안에 id로 유저정보 찾음
        # 닉네임을 보내줌
        userinfo = db.infos.find_one({'ID': payload['ID']}, {'_id': 0})
        return jsonify({'result': 'success', 'Nickname': userinfo['Nickname']})
    except jwt.ExpiredSignatureError:
        # 만료시간이 지났으면 에러발생
        return jsonify({'result': 'fail', 'msg': '로그인 시간이 만료되었습니다.'})


# @app.route('/Login', methods=['GET'])
# def check_infos():
#     infos = list(db.infos.find({}, {'_id': 0}))
#     return jsonify({'result': 'success', 'msg': '회원가입을 부탁드립니다'})

# 아이디 중복확인

# def joongbok(request):
#     username = request.GET.get('ID')
#     try:
#         # 중복 검사 실패
#         user = User.objects.get(ID=username)
#     except:
#         # 중복 검사 성공
#         user = None
#     if user is None:
#         overlap = "pass"
#     else:
#         overlap = "fail"
#     context = {'overlap': overlap}
#     return JsonResponse(context)


# 로그인 API
# @app.route('/login', methods=["POST"])
# def login():
#     if current_user.is_authenticated:
#         redirect_url = url_for('index')
#         return jsonify(loggedIn=True, redirectUrl=redirect_url)
#
#     userID = request.form.get('ID', '').strip()
#     userPassword = request.form.get('Password', '').strip()
#     user = User.query.filter_by(ID=userID).first()
#     if user and util.encrypt_password(userPassword, user.salt) == user.Password:
#         logged_in_user = CurrentUser(user)
#         login_user(logged_in_user)
#         redirect_url = url_for('index')
#         return jsonify(loggedIn=True, redirectUrl=redirect_url)
#     else:
#         return jsonify(loggedIn=False, error='Invalid Email/Password')


if __name__ == '__main__':
    app.run('localhost', port=5001, debug=True)
