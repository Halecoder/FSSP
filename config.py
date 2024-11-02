class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://username:secret@databaseIP:3306/dbname'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'e4b6f3c0a19a4ef7b3b5d2c1f5abxxxx' # 随意修改
    SECRET_IDKEY = b'A3F1C9D4B6E2F8074D5C3B2A1E6FXXXX'  # 必须是 16 字节

    # 开关：是否强制要求 OAuth 验证，填 True / False
    FORCE_OAUTH = True

    # OAuth2 参数
    OAUTH_CLIENT_ID = 'wN3LDWsuY57FQcXXXXXXeOBnqGtA1'
    OAUTH_CLIENT_SECRET = '4bGjXKWViAXXXXXXNbjoB1oMxq7uZJ0m'
    OAUTH_REDIRECT_URI = 'https://[网站域名]/auth/callback'
    OAUTH_AUTHORIZATION_ENDPOINT = 'https://connect.linux.do/oauth2/authorize'
    OAUTH_TOKEN_ENDPOINT = 'https://connect.linux.do/oauth2/token'
    OAUTH_USER_ENDPOINT = 'https://connect.linux.do/api/user'
    
    # 失效报告阈值，超过这个阈值会自动删除订阅
    REPORT_THRESHOLD = 5