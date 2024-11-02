from flask import Flask, session, redirect, request, Response, jsonify, url_for, render_template, flash
from flask import make_response
import os
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.mysql import VARCHAR
from urllib.parse import urlparse
from datetime import datetime
from config import Config
import uuid
import urllib3
from urllib.parse import urljoin

import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import traceback

import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 禁用不安全请求的警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config.from_object(Config)  # 导入配置

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# OAuth2 参数通过配置文件获取
CLIENT_ID = app.config['OAUTH_CLIENT_ID']
CLIENT_SECRET = app.config['OAUTH_CLIENT_SECRET']
REDIRECT_URI = app.config['OAUTH_REDIRECT_URI']
AUTHORIZATION_ENDPOINT = app.config['OAUTH_AUTHORIZATION_ENDPOINT']
TOKEN_ENDPOINT = app.config['OAUTH_TOKEN_ENDPOINT']
USER_ENDPOINT = app.config['OAUTH_USER_ENDPOINT']

# 多对多关系表，用于存储订阅和标签的关系
subscription_tags = db.Table('subscription_tags',
    db.Column('subscription_id', db.Integer, db.ForeignKey('subscription.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

# 订阅标签模型
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)

# 订阅模型
class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), nullable=False)  # 记录发布者的用户ID
    is_self_built = db.Column(db.String(10), nullable=False)
    remaining_data = db.Column(db.Float, nullable=False)
    expiry_date = db.Column(db.String(20), nullable=True, default='无限')
    includes_aff = db.Column(db.String(10), nullable=True)
    provider_url = db.Column(db.String(255), nullable=True)
    subscription_url = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    additional_information = db.Column(db.String(80), nullable=True)  # 新增的简介列
    tags = db.relationship('Tag', secondary=subscription_tags, lazy='subquery',
        backref=db.backref('subscriptions', lazy=True))
    likes = db.Column(db.Integer, default=0)  # 收获的爱心数
    reports = db.Column(db.Integer, default=0)  # 订阅失效报告数


    # 新增级联删除
    actions = db.relationship('UserAction', backref='subscription', cascade='all, delete-orphan')

    def get_summary_info(self):
        summary = []
        if self.is_self_built == '自购':
            summary.append('自购分享')
        elif self.is_self_built == '自建':
            summary.append('DIY')
        elif self.is_self_built == '网上搜集':
            summary.append('搜集')
        
        for tag in self.tags:
            if tag.name == '解锁流媒体':
                summary.append('流')
            elif tag.name == '解锁 AI 服务':
                summary.append('AI')
            elif tag.name == '高质量 IP':
                summary.append('IP')
            # 移除 FSSP 和 Public 标签的显示
            # elif tag.name == 'FSSP':
            #     summary.append('FSSP')
            # elif tag.name == 'Public':
            #     summary.append('Public')
        return ' | '.join(summary)

    def get_full_tags(self):
        tags_list = [self.is_self_built]
        tags_list.extend([tag.name for tag in self.tags])
        return ', '.join(tags_list)

    def __repr__(self):
        return f'<Subscription {self.subscription_url}>'

    def like(self):
        self.likes += 1
        db.session.commit()

    def report(self):
        self.reports += 1
        if self.reports >= app.config['REPORT_THRESHOLD']:
            db.session.delete(self)
        db.session.commit()

    def update(self, data):
        self.is_self_built = data.get('is_self_built', self.is_self_built)
        self.remaining_data = data.get('remaining_data', self.remaining_data)
        self.expiry_date = data.get('expiry_date', self.expiry_date)
        self.includes_aff = data.get('includes_aff', self.includes_aff)
        self.provider_url = data.get('provider_url', self.provider_url)
        self.subscription_url = data.get('subscription_url', self.subscription_url)
        self.tags = []
        for tag_name in data.get('tags', []):
            tag = Tag.query.filter_by(name=tag_name).first()
            if tag:
                self.tags.append(tag)
        db.session.commit()

# 用户操作模型，记录每个用户对订阅的点赞和举报操作
class UserAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), nullable=False)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscription.id'), nullable=False)
    liked = db.Column(db.Integer, default=0)  # 记录用户的点赞次数
    reported = db.Column(db.Boolean, default=False)  # 记录用户是否举报过

    def __repr__(self):
        return f'<UserAction user_id={self.user_id}, subscription_id={self.subscription_id}, liked={self.liked}, reported={self.reported}>'

# 用户信息模型，对应 user_info 表
class UserInfo(db.Model):
    __tablename__ = 'user_info'  # 指定表名

    id = db.Column(db.String(255), primary_key=True)  # 用户ID
    username = db.Column(db.String(255), nullable=False)  # 论坛用户名
    name = db.Column(db.String(255), nullable=True)  # 论坛用户昵称
    trust_level = db.Column(db.Integer, nullable=False)  # 信任等级
    status = db.Column(db.String(50), nullable=False, default='normal', server_default='normal')  # 用户状态
    uuid = db.Column(db.String(36), nullable=False, unique=True, default=lambda: str(uuid.uuid4()))  # 随机生成的 UUID
    settings_1 = db.Column(db.Integer, nullable=False)  # 信任等级
    avatar_url = db.Column(db.String(255), nullable=True)  # 用户头像URL

    def __repr__(self):
        return f'<UserInfo id={self.id}, username={self.username}, trust_level={self.trust_level}, status={self.status}, uuid={self.uuid}>'


# 输入验证函数
def validate_input(is_self_built, remaining_data, expiry_date, includes_aff, provider_url, subscription_url):
    errors = []

    # 验证 is_self_built
    if is_self_built not in ['自建', '自购', '网上搜集']:
        errors.append("简略信息必须是'自建'，'自购'或'网上搜集'。")

    # 验证 remaining_data
    try:
        remaining_data = float(remaining_data)
        if remaining_data < 0:
            errors.append("剩余流量必须是一个正数。")
    except ValueError:
        errors.append("剩余流量必须是一个数字。")

    # 验证 includes_aff
    if includes_aff not in ['不含 AFF', '双方获利 AFF', '分享者获利 AFF']:
        errors.append("推广选项必须是 '不含 AFF' 或 '双方获利 AFF' 或 '分享者获利 AFF'。")

    # 验证 provider_url
    if provider_url and len(provider_url) > 255:
        errors.append("服务提供商 URL 长度不能超过 255 字符。")

    # 验证 subscription_url
    if not subscription_url or not urlparse(subscription_url).scheme:
        errors.append("请输入有效的订阅 URL。")
    elif len(subscription_url) > 8000:
        errors.append("订阅 URL 长度不能超过 8000 字符。")

    return errors

@app.route('/like/<int:subscription_id>', methods=['POST'])
def like_subscription(subscription_id):
    if 'user_info' not in session:
        return jsonify({'status': 'error', 'message': '请先登录'}), 401

    user_id = session['user_info']['id']
    action = UserAction.query.filter_by(user_id=user_id, subscription_id=subscription_id).first()

    if action is None:
        action = UserAction(user_id=user_id, subscription_id=subscription_id, liked=1)
        db.session.add(action)
        subscription = Subscription.query.get_or_404(subscription_id)
        subscription.like()
        return jsonify({'status': 'success', 'likes': subscription.likes})
    elif action.liked < 2:
        action.liked += 1
        subscription = Subscription.query.get_or_404(subscription_id)
        subscription.like()
        return jsonify({'status': 'success', 'likes': subscription.likes})
    else:
        return jsonify({'status': 'error', 'message': '你已经点赞过两次了'}), 400

@app.route('/report/<int:subscription_id>', methods=['POST'])
def report_subscription(subscription_id):
    if 'user_info' not in session:
        return jsonify({'status': 'error', 'message': '请先登录'}), 401

    user_id = session['user_info']['id']
    action = UserAction.query.filter_by(user_id=user_id, subscription_id=subscription_id).first()

    if action is None:
        action = UserAction(user_id=user_id, subscription_id=subscription_id, reported=True)
        db.session.add(action)
        subscription = Subscription.query.get_or_404(subscription_id)
        subscription.report()
        return jsonify({'status': 'success', 'reports': subscription.reports})
    elif not action.reported:
        action.reported = True
        subscription = Subscription.query.get_or_404(subscription_id)
        subscription.report()
        return jsonify({'status': 'success', 'reports': subscription.reports})
    else:
        return jsonify({'status': 'error', 'message': '你已经报告过这个订阅失效了'}), 400

@app.route('/oauth2/initiate')
def initiate_auth():
    session['oauth_state'] = os.urandom(16).hex()
    authorization_url = f"{AUTHORIZATION_ENDPOINT}?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}&state={session['oauth_state']}"
    return redirect(authorization_url)

@app.route('/auth/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')

    if state != session.get('oauth_state'):
        return 'State value does not match', 401

    # 请求token
    auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    headers = {'Accept': 'application/json'}
    response = requests.post(TOKEN_ENDPOINT, auth=auth, data=data, headers=headers)

    if response.status_code == 200:
        access_token = response.json().get('access_token')
        user_response = requests.get(USER_ENDPOINT, headers={'Authorization': 'Bearer ' + access_token})
        if user_response.status_code == 200:
            user_info = user_response.json()
            session['user_info'] = user_info
            session['authenticated'] = True

            # 检查用户的 trust_level 和 status
            user_id = user_info['id']
            existing_user = UserInfo.query.filter_by(id=user_id).first()

            # 获取头像 URL
            avatar_url = None
            initial_url = f"https://linux.do/user_avatar/linux.do/{user_info['username']}/288/1.png"
            try:
                avatar_response = requests.head(initial_url, allow_redirects=True)
                if avatar_response.status_code == 200:
                    avatar_url = avatar_response.url
            except requests.RequestException:
                pass

            if not avatar_url:
                # 使用默认头像 URL 如果获取失败
                avatar_url = "https://linux.do/user_avatar/linux.do/bywenshu/288/165240_2.png"

            if existing_user:
                # 如果用户已经存在，更新用户信息
                existing_user.username = user_info['username']
                existing_user.name = user_info['name']
                existing_user.trust_level = user_info['trust_level']

                # 检查 settings_1 是否为空
                if existing_user.settings_1 is None:
                    existing_user.settings_1 = 0

                # 更新头像 URL
                existing_user.avatar_url = avatar_url

                # 检查用户状态
                if existing_user.status == 'banned':
                    return redirect(url_for('banned'))

            else:
                # 如果用户不存在，创建新用户
                new_user = UserInfo(
                    id=user_info['id'],
                    username=user_info['username'],
                    name=user_info['name'],
                    trust_level=user_info['trust_level'],
                    settings_1=0,  # 新用户 settings_1 默认设置为 0
                    avatar_url=avatar_url  # 设置头像 URL
                )
                db.session.add(new_user)

            # 提交更改
            db.session.commit()

            return redirect(url_for('index'))
        else:
            return 'Failed to fetch user info', user_response.status_code
    else:
        return 'Failed to fetch access token', response.status_code





@app.route('/')
@app.route('/page/<int:page>')
def index(page=1):
    if app.config['FORCE_OAUTH']:
        if not session.get('authenticated'):
            return redirect(url_for('auth_warning', reason='not_authenticated'))
        user_id = int(session['user_info']['id'])
        if user_id not in [29403, 50540] and session['user_info']['trust_level'] < 2:
            return redirect(url_for('auth_warning', reason='low_trust_level'))

    per_page = 12
    pagination = Subscription.query.order_by(Subscription.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    subscriptions = pagination.items

    # 为每个订阅获取用户名和昵称，并生成加密的 ID
    for subscription in subscriptions:
        user = UserInfo.query.filter_by(id=subscription.user_id).first()
        if user:
            subscription.user_name = user.name if user.name else user.username  # 显示用的名字（昵称或用户名）
            subscription.user_username = user.username  # 链接用的用户名
        else:
            subscription.user_name = "雷锋同志（未能获取用户名）"
            subscription.user_username = "-unknown"
        
        # 为每个订阅生成加密的 ID
        try:
            subscription.encrypted_id = encrypt_id(subscription.id)
        except Exception as e:
            subscription.encrypted_id = None
            app.logger.error(f"加密订阅 ID 失败：{e}")

    # 获取 FSSP、Public 和 Proxied 标签
    fssp_tag = Tag.query.filter_by(name='FSSP').first()
    public_tag = Tag.query.filter_by(name='Public').first()
    proxied_tag = Tag.query.filter_by(name='Proxied').first()

    # 动态检查和附加标签
    for subscription in subscriptions:
        has_fssp_or_public = any(tag.name in ['FSSP', 'Public'] for tag in subscription.tags)
        if not has_fssp_or_public:
            if subscription.is_self_built == '网上搜集':
                if public_tag:
                    subscription.tags.append(public_tag)
            else:
                if fssp_tag:
                    subscription.tags.append(fssp_tag)
        
        # 检查是否包含 'Proxied' 标签
        if any(tag.name == 'Proxied' for tag in subscription.tags):
            # 设置 subscription_url 为代理路由的加密链接
            if subscription.encrypted_id:
                subscription.subscription_url = url_for(
                'proxy',
                encrypted_id=subscription.encrypted_id,
                _external=True,
                _scheme='https'  # 强制使用 HTTPS 协议
            )

            else:
                # 如果加密 ID 生成失败，设置为提示信息
                subscription.subscription_url = "分享者设置了代理以保护原订阅，原订阅已隐藏。"
        else:
            # 保留原始的 subscription_url
            pass

    return render_template('index.html', subscriptions=subscriptions, pagination=pagination)



@app.route('/auth_warning')
def auth_warning():
    if not app.config['FORCE_OAUTH']:
        return redirect(url_for('index'))
    reason = request.args.get('reason', '')
    return render_template('auth_warning.html', reason=reason)


@app.route('/banned')
def banned():
    # 创建响应对象
    response = make_response(render_template('banned.html'))
    
    # 清空所有 Cookies
    for cookie in request.cookies:
        response.delete_cookie(cookie)
    
    # 清除 session 以确保安全
    session.clear()
    
    return response

@app.route('/get_avatar_noredirect/<username>', methods=['GET'])
def get_avatar_noredirect(username):
    # 从数据库中检索 username 对应的用户信息
    user = UserInfo.query.filter_by(username=username).first()

    if user and user.avatar_url:
        # 如果 avatar_url 已存在于数据库中，直接重定向至该 URL
        return redirect(user.avatar_url)
    else:
        # 构造初始的头像 URL
        initial_url = f"https://linux.do/user_avatar/linux.do/{username}/288/2.png"

        try:
            # 发送 HEAD 请求以获取重定向的 URL
            response = requests.head(initial_url, allow_redirects=True)

            # 获取最终重定向的 URL
            final_url = response.url

            if user:
                # 如果用户存在，更新 avatar_url
                user.avatar_url = final_url
            else:
                # 如果用户不存在，创建新的用户记录
                user = UserInfo(username=username, avatar_url=final_url)
                db.session.add(user)

            # 提交数据库事务
            db.session.commit()

            # 重定向至最终的头像 URL
            return redirect(final_url)
        except requests.RequestException as e:
            # 处理请求异常
            return f"Error occurred: {str(e)}", 500

@app.route('/share', methods=['GET', 'POST'])
def share():
    if app.config['FORCE_OAUTH']:
        if not session.get('authenticated'):
            return redirect(url_for('auth_warning', reason='not_authenticated'))
        user_id = int(session['user_info']['id'])
        if user_id not in [29403, 50540] and session['user_info']['trust_level'] < 2:
            return redirect(url_for('auth_warning', reason='low_trust_level'))
    if request.method == 'POST':
        form_data = {
            'is_self_built': request.form.get('is_self_built'),
            'remaining_data': request.form.get('remaining_data'),
            'expiry_date': request.form.get('expiry_date', '无有效期'),
            'includes_aff': request.form.get('includes_aff', '不含 AFF'),
            'provider_url': request.form.get('provider_url'),
            'subscription_url': request.form.get('subscription_url'),
            'tags': request.form.getlist('tags'),
            'authorization': request.form.get('authorization'),  # 添加授权信息
            'additional_information': request.form.get('subscription_description', '')  # 新增简介信息
        }

        # 调用 share_single_subscription 函数来处理
        share_single_subscription(form_data)
        return redirect(url_for('index'))

    tags = Tag.query.all()
    return render_template('share.html', tags=tags)


@app.route('/bulk_share', methods=['POST'])
def bulk_share():
    user_info = session.get('user_info')

    if not user_info:
        flash('用户未登录或会话已过期，请重新登录。', 'danger')
        return redirect(url_for('initiate_auth'))

    forms = request.form.to_dict(flat=False)

    for i in range(len(forms['is_self_built'])):
        # 构造每个表单数据的字典
        tags_key = f'tags_{i}'  # 获取唯一的 tags 名称
        form_data = {
            'is_self_built': forms['is_self_built'][i],
            'remaining_data': forms['remaining_data'][i],
            'expiry_date': forms['expiry_date'][i],
            'includes_aff': forms['includes_aff'][i],
            'provider_url': forms['provider_url'][i] if forms['provider_url'][i] else '未提供',
            'subscription_url': forms['subscription_url'][i],
            'tags': forms.get(tags_key, [''])[0].split(','),  # 分解逗号分隔的标签
            'authorization': forms['authorization'][i],
            'additional_information': forms.get(f'description_{i}', [''])[0]  # 获取对应的简介信息
        }

        share_single_subscription(form_data, user_info)

    flash('所有订阅均已成功提交', 'success')
    return redirect(url_for('manage_subscriptions'))


def share_single_subscription(form_data, user_info=None):
    # 如果没有传递 user_info，则尝试从 session 中获取
    if not user_info:
        user_info = session.get('user_info')
    user_id = user_info['id'] if user_info else None

    if not user_id:
        raise KeyError('User not authenticated')

    errors = validate_input(
        form_data['is_self_built'],
        form_data['remaining_data'],
        form_data['expiry_date'],
        form_data['includes_aff'],
        form_data['provider_url'],
        form_data['subscription_url']
    )
    if errors:
        for error in errors:
            flash(error, 'danger')
        return

    try:
        new_subscription = Subscription(
            user_id=user_id,
            is_self_built=form_data['is_self_built'],
            remaining_data=float(form_data['remaining_data']),
            expiry_date=form_data['expiry_date'] if form_data['expiry_date'] else '无有效期',
            includes_aff=form_data['includes_aff'],
            provider_url=form_data['provider_url'],
            subscription_url=form_data['subscription_url'],
            additional_information=form_data['additional_information']  # 添加简介信息
        )

        # 先添加 new_subscription 到 db.session
        db.session.add(new_subscription)
        db.session.flush()  # 确保 new_subscription 被分配了 ID

        # 确保标签正确添加
        for tag_name in form_data.get('tags', []):
            tag = Tag.query.filter_by(name=tag_name).first()
            if tag and tag not in new_subscription.tags:
                new_subscription.tags.append(tag)

        # 处理授权信息标签
        authorization = form_data.get('authorization')
        if authorization == 'FSSP':
            fssp_tag = Tag.query.filter_by(name='FSSP').first()
            if fssp_tag and fssp_tag not in new_subscription.tags:
                new_subscription.tags.append(fssp_tag)
        elif authorization == 'Public':
            public_tag = Tag.query.filter_by(name='Public').first()
            if public_tag and public_tag not in new_subscription.tags:
                new_subscription.tags.append(public_tag)

        # 处理代理信息标签
        proxy = form_data.get('proxy')
        if proxy == 'Proxied':
            proxied_tag = Tag.query.filter_by(name='Proxied').first()
            if proxied_tag and proxied_tag not in new_subscription.tags:
                new_subscription.tags.append(proxied_tag)

        db.session.commit()  # 提交事务
        flash('订阅链接已成功分享', 'success')
    except IntegrityError:
        db.session.rollback()
        flash('该订阅URL已存在', 'danger')


@app.route('/get_user_name/<int:user_id>', methods=['GET'])
def get_user_name(user_id):
    user = UserInfo.query.filter_by(id=user_id).first()
    if not user:
        return "雷锋同志（未能获取用户名）"
    
    user_name = user.name if user.name else user.username
    return user_name


@app.route('/get_avatar_by_id/<id>', methods=['GET'])
def get_avatar_by_id(id):
    user = UserInfo.query.filter_by(id=id).first()

    if user:
        if user.avatar_url:
            return redirect(user.avatar_url)
        else:
            initial_url = f"https://linux.do/user_avatar/linux.do/{user.username}/288/1.png"
            try:
                response = requests.head(initial_url, allow_redirects=True)
                
                # 检查是否成功获取头像 URL
                if response.status_code == 200:
                    final_url = response.url
                    user.avatar_url = final_url
                    db.session.commit()
                    return redirect(final_url)
                else:
                    # 如果获取失败，重定向至默认头像
                    return redirect("https://linux.do/user_avatar/linux.do/bywenshu/288/165240_2.png")
            except requests.RequestException:
                return redirect("https://linux.do/user_avatar/linux.do/bywenshu/288/165240_2.png")
    else:
        # 如果用户不存在，重定向至默认头像
        return redirect("https://linux.do/user_avatar/linux.do/bywenshu/288/165240_2.png")



@app.route('/get_avatar/<username>', methods=['GET'])
def get_avatar(username):
    user = UserInfo.query.filter_by(username=username).first()

    if user and user.avatar_url:
        return redirect(user.avatar_url)
    else:
        initial_url = f"https://linux.do/user_avatar/linux.do/{username}/288/1.png"
        try:
            response = requests.head(initial_url, allow_redirects=True)
            final_url = response.url

            if user:
                user.avatar_url = final_url
            else:
                user = UserInfo(username=username, avatar_url=final_url)
                db.session.add(user)

            db.session.commit()

            return redirect(final_url)
        except requests.RequestException as e:
            return f"Error occurred: {str(e)}", 500


@app.route('/manage_subscriptions')
def manage_subscriptions():
    if app.config['FORCE_OAUTH']:
        if not session.get('authenticated'):
            return redirect(url_for('auth_warning', reason='not_authenticated'))
        user_id = int(session['user_info']['id'])
        if user_id not in [29403, 50540] and session['user_info']['trust_level'] < 2:
            return redirect(url_for('auth_warning', reason='low_trust_level'))

    user_id = session['user_info']['id']

    # 获取用户的订阅
    if int(user_id) in [29403, 29816]:  # 管理员权限，获取所有用户的订阅
        subscriptions = Subscription.query.order_by(Subscription.created_at.desc()).all()
    else:
        subscriptions = Subscription.query.filter_by(user_id=user_id).order_by(Subscription.created_at.desc()).all()

    # 动态检查和附加标签
    for subscription in subscriptions:
        has_fssp_or_public = any(tag.name in ['FSSP', 'Public'] for tag in subscription.tags)
        if not has_fssp_or_public:
            if subscription.is_self_built == '网上搜集':
                public_tag = Tag.query.filter_by(name='Public').first()
                if public_tag:
                    subscription.tags.append(public_tag)
            else:
                fssp_tag = Tag.query.filter_by(name='FSSP').first()
                if fssp_tag:
                    subscription.tags.append(fssp_tag)

    return render_template('manage_subscriptions.html', subscriptions=subscriptions)



@app.route('/edit_subscription/<int:subscription_id>', methods=['GET', 'POST'])
def edit_subscription(subscription_id):
    if 'user_info' not in session or not session.get('authenticated'):
        return redirect(url_for('initiate_auth'))

    user_id = session['user_info']['id']
    subscription = Subscription.query.get_or_404(subscription_id)

    if subscription.user_id != user_id:
        return redirect(url_for('manage_subscriptions'))

    if request.method == 'POST':
        form_data = {
            'is_self_built': request.form.get('is_self_built'),
            'remaining_data': request.form.get('remaining_data'),
            'expiry_date': request.form.get('expiry_date') or '无有效期',
            'includes_aff': request.form.get('includes_aff', '不含 AFF'),
            'provider_url': request.form.get('provider_url'),
            'subscription_url': request.form.get('subscription_url'),
            'tags': request.form.getlist('tags'),
            'authorization': request.form.get('authorization'),
            'additional_information': request.form.get('additional_information')  # 新增描述字段
        }

        # 验证输入
        errors = validate_input(
            form_data['is_self_built'],
            form_data['remaining_data'],
            form_data['expiry_date'],
            form_data['includes_aff'],
            form_data['provider_url'],
            form_data['subscription_url']
        )
        if errors:
            for error in errors:
                flash(error, 'danger')
            return redirect(url_for('edit_subscription', subscription_id=subscription.id))

        # 更新订阅信息
        subscription.is_self_built = form_data['is_self_built']
        subscription.remaining_data = float(form_data['remaining_data'])
        subscription.expiry_date = form_data['expiry_date']
        subscription.includes_aff = form_data['includes_aff']
        subscription.provider_url = form_data['provider_url']
        subscription.subscription_url = form_data['subscription_url']
        subscription.additional_information = form_data['additional_information']  # 更新订阅描述

        # 更新标签
        subscription.tags.clear()
        for tag_name in form_data['tags']:
            tag = Tag.query.filter_by(name=tag_name).first()
            if tag:
                subscription.tags.append(tag)

        # 更新授权信息
        fssp_tag = Tag.query.filter_by(name='FSSP').first()
        public_tag = Tag.query.filter_by(name='Public').first()

        # 先清除已有的授权标签
        if fssp_tag in subscription.tags:
            subscription.tags.remove(fssp_tag)
        if public_tag in subscription.tags:
            subscription.tags.remove(public_tag)

        # 添加新的授权标签
        if form_data['authorization'] == 'FSSP':
            if fssp_tag not in subscription.tags:
                subscription.tags.append(fssp_tag)
        elif form_data['authorization'] == 'Public':
            if public_tag not in subscription.tags:
                subscription.tags.append(public_tag)

        db.session.commit()
        flash('订阅已成功更新', 'success')
        return redirect(url_for('manage_subscriptions'))

    # GET 请求处理
    tags = Tag.query.all()
    
    # 确定当前授权状态
    current_authorization = 'Public'
    if any(tag.name == 'FSSP' for tag in subscription.tags):
        current_authorization = 'FSSP'
    elif any(tag.name == 'Public' for tag in subscription.tags):
        current_authorization = 'Public'

    return render_template('edit_subscription.html', subscription=subscription, tags=tags, current_authorization=current_authorization)



@app.route('/delete_subscription/<int:subscription_id>', methods=['POST'])
def delete_subscription(subscription_id):
    try:
        # 首先删除与该 subscription_id 相关联的 UserAction 记录
        UserAction.query.filter_by(subscription_id=subscription_id).delete()
        db.session.commit()

        # 然后删除 subscription 记录
        subscription = Subscription.query.get_or_404(subscription_id)
        db.session.delete(subscription)
        db.session.commit()
        flash('订阅已成功删除', 'success')
    except IntegrityError as e:
        db.session.rollback()
        flash(f'删除失败: {str(e)}', 'danger')
    return redirect(url_for('manage_subscriptions'))



# 使用 16 字节的密钥，请替换为您的独有密钥
SECRET_KEY = app.config['SECRET_IDKEY']

def encrypt_id(id):
    id_bytes = id.to_bytes((id.bit_length() + 7) // 8 or 1, byteorder='big')
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(id_bytes) + padder.finalize()
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.ECB())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_id = base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8').rstrip('=')
    return encrypted_id

def decrypt_id(encrypted_id_str):
    padding_needed = (4 - len(encrypted_id_str) % 4) % 4
    encrypted_id_str += '=' * padding_needed
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_id_str.encode('utf-8'))
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.ECB())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    id_bytes = unpadder.update(padded_data) + unpadder.finalize()
    id = int.from_bytes(id_bytes, byteorder='big')
    return id

@app.route('/getsub/<encrypted_id>', defaults={'path': ''}, methods=['GET'])
@app.route('/getsub/<encrypted_id>/<path:path>', methods=['GET'])
def proxy(encrypted_id, path):
    try:
        # 解密得到原始 id
        id = decrypt_id(encrypted_id)
        
        # 查询数据库，获取对应的订阅
        subscription = Subscription.query.get(id)
        if not subscription:
            return 'Subscription not found', 404

        # 获取目标 URL
        base_url = subscription.subscription_url.strip()
        if path:
            target_url = urljoin(base_url.rstrip('/') + '/', path)
        else:
            target_url = base_url

        # 获取查询参数
        params = request.args.to_dict(flat=False)

        # 准备请求头，保留必要头部
        headers = {key: value for key, value in request.headers if key.lower() not in ['host', 'content-length', 'accept-encoding']}
        # 设置 Accept-Encoding，明确告诉服务器不压缩响应
        headers['Accept-Encoding'] = 'identity'

        # 设置 User-Agent 为 Chrome UA
        headers['User-Agent'] = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                                  'Chrome/92.0.4515.159 Safari/537.36')

        # 从环境变量中获取代理 URL，或使用默认值
        PROXY_URL = os.getenv('SOCKS5_PROXY_URL', 'socks5h://username:secret@10.0.0.227:1234')

        # 配置 SOCKS5 代理
        proxies = {
            'http': PROXY_URL,
            'https': PROXY_URL
        }

        # 创建会话并配置重试策略
        session = requests.Session()
        retry_strategy = Retry(
            total=5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # 发送请求，使用代理和会话
        resp = session.get(
            url=target_url,
            headers=headers,
            params=params,
            allow_redirects=True,
            verify=False,  # 根据需要设置 SSL 验证
            proxies=proxies,
            timeout=10  # 设置超时时间（秒）
        )

        # 输出响应状态码和头部，便于调试
        print(f"Response status code: {resp.status_code}")
        print(f"Response headers: {resp.headers}")

        # 读取响应内容，使用 resp.content
        content = resp.content

        # 输出内容长度和前100字节，帮助调试
        print(f"Content length: {len(content)}")
        print(f"First 100 bytes of content: {content[:100]}")

        # 构造响应，移除 'Content-Encoding' 和 'Transfer-Encoding' 头部
        excluded_headers = ['content-length', 'transfer-encoding', 'connection', 'content-encoding']
        response_headers = [(name, value) for (name, value) in resp.headers.items() if name.lower() not in excluded_headers]

        # 添加正确的 Content-Length 头部
        response_headers.append(('Content-Length', str(len(content))))

        # 返回响应给客户端
        response = Response(content, resp.status_code, response_headers)

        # 如果需要，设置 CORS 头部
        response.headers['Access-Control-Allow-Origin'] = '*'

        return response

    except Exception as e:
        # 输出错误信息到终端
        print("An error occurred:")
        traceback.print_exc()
        return f"An internal error occurred: {e}", 500



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # 初始标签
        default_tags = ['解锁流媒体', '解锁 AI 服务', '高质量 IP', 'FSSP', 'Public', 'Proxied']
        for tag_name in default_tags:
            tag = Tag.query.filter_by(name=tag_name).first()
            if not tag:
                db.session.add(Tag(name=tag_name))
                print(f"Tag {tag_name} added to database")  # 调试输出
            else:
                print(f"Tag {tag_name} already exists in database")  # 调试输出
        db.session.commit()
    app.run(host='0.0.0.0', port=9527, debug=True)


