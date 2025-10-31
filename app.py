from mongoengine import *
import datetime
import uuid
import json
import secrets
from datetime import date
import requests
from flask import request
from flask import Flask
import regex as re
import os

app = Flask(__name__)


# Get port from environment variable (Railway will provide this)
port = int(os.environ.get("PORT", 5000))

# Use environment variables for database configuration
url_db = os.environ.get('MONGODB_URL')
db_user = os.environ.get('DB_USER')
db_pass = os.environ.get('DB_PASS')
db_name = os.environ.get('DB_NAME')

# Validate that all required environment variables are set
required_env_vars = ['MONGODB_URL', 'DB_USER', 'DB_PASS', 'DB_NAME']
missing_vars = [var for var in required_env_vars if not os.environ.get(var)]

if missing_vars:
    print(f"Warning: Missing environment variables: {missing_vars}")

try:
    if all([url_db, db_user, db_pass, db_name]):
        con = connect(
            host=url_db,
            username=db_user,
            password=db_pass,
            db=db_name)
        
        print("Successfully connected to MongoDB")
    else:
        print("Database configuration incomplete - waiting for environment variables")
except Exception as e:
    print(f"Database connection error: {e}")


class users_auth(Document):
  user_id = StringField(required = True)
  user_email = StringField(required = True)
  pwd_hash = StringField(required = True)


class users_emails(Document):
  user_id = StringField(required = True)
  user_email = StringField(required = True)
  user_name = StringField(required = True)
  user_surname = StringField(required = True)


class sessions_info(Document):
  token_session = StringField(required = True)
  user_email = StringField(required = True)
  role = StringField(choices = ['manager', 'employee'], default = 'employee')
  subdivision_list_session = ListField(StringField(), required = True, default = [])
  expires_at = DateTimeField(required = True)


class tasks_master_list(Document):
  subdivision_name = StringField(required = True)
  tasks_list = DictField(
        required=True,
        help_text="JSON, содержащий записи по всем задачам конкретного отдела или группы"
    )


class fte_records(Document):
  record_id = StringField(required = True)
  employee_id = StringField(required = True)
  fte_date = DateTimeField(required = True)
  task_id = StringField(required = True)
  task_name = StringField(required = True)
  task_duration = FloatField(required = True)
  record_created_at = DateTimeField(required = True)
  record_updated_at = DateTimeField(required = False)
  is_free_to_update = BooleanField(required = True, default=True)
  is_deleted = BooleanField(required = True, default=False)


  #-----------------------------------------------------
# зарегистрироваться в сервисе
@app.route('/fte_records/register', methods=['POST'])
def validate_register_data():
  request_body = request.get_json()

# 1. Проверка наличия тела запроса
  if not request_body:
    return {
      "error": "Тело запроса не может быть пустым"}, 400

  required_fields = ["email_input", "pwd_input", "user_name_input", "user_surname_input"]
  missing_fields = [field for field in required_fields if field not in request_body]

  if missing_fields:
    return {
      "error": "Отсутствуют обязательные поля",
      "missing_fields": missing_fields,
      "message": f"Необходимо заполнить: {', '.join(missing_fields)}"}, 400

  # 3. Проверка пустых значений
  empty_fields = []
  for field in required_fields:
    if not request_body[field] or not str(request_body[field]).strip():
      empty_fields.append(field)

  if empty_fields:
    return {
      "error": "Обязательные поля не могут быть пустыми",
      "empty_fields": empty_fields,
      "message": f"Заполните поля: {', '.join(empty_fields)}"}, 400

  email_input = request_body["email_input"].strip()
  pwd_input = request_body["pwd_input"].strip()

  email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
  if not re.match(email_regex, email_input):
     return {
      "error": "Некорректный формат email",
      "message": "Введите корректный email адрес (пример: user@example.com)"
                }, 400


  # 6. Валидация пароля
  if len(pwd_input) < 8:
    return {
      "error": "Слишком короткий пароль",
      "message": "Пароль должен содержать минимум 8 символов"}, 400

#-----------------------------------------------------
  emails_from_db = []
  json_data = users_emails.objects().to_json()
  users_list = json.loads(json_data)
  emails_from_db = [user['user_email'] for user in users_list if 'user_email' in user]
  if request_body['email_input'] in emails_from_db:
    return {
        "error" : "В системе уже существует аккаунт с введенным email.",
    }, 409

  else:
    try:
      users_auth(
        user_id = uuid.uuid4().hex,
        user_email = request_body['email_input'],
        pwd_hash = str(hash(request_body['pwd_input']))).save()
    except Exception as e:
      return {"error": "Ошибка сервера. Попробуйте повторить позже"}, 500

    user_info = users_auth.objects(user_email = request_body['email_input']).to_json()

    try:
      users_emails(
                  user_id = json.loads(user_info)[0]['user_id'],
                  user_email = json.loads(user_info)[0]['user_email'],
                  user_name = request_body['user_name_input'],
                  user_surname = request_body['user_surname_input']
                  ).save()
    except Exception as e:
      return {"error": "Ошибка сервера. Попробуйте повторить позже"}, 500


    user_info_email = users_emails.objects(user_id = json.loads(user_info)[0]['user_id']).to_json()
    return {
        "message" : "Вы успешно зарегистрированы в системе",
        "user_id": json.loads(user_info_email)[0]['user_id'],
        "user_email": json.loads(user_info_email)[0]['user_email'],
        "user_name": json.loads(user_info_email)[0]['user_name'],
        "user_surname": json.loads(user_info_email)[0]['user_surname']
    }, 201

#-----------------------------------------------------
# авторизоваться в сервисе
@app.route('/fte_records/signin', methods=['POST'])
def sign_in():
  request_body = request.get_json()

  # 1. Проверка наличия тела запроса
  if not request_body:
    return {
      "error": "Тело запроса не может быть пустым"}, 400

  required_fields = ["email_input", "pwd_input"]
  missing_fields = [field for field in required_fields if field not in request_body]

  if missing_fields:
    return {
      "error": "Отсутствуют обязательные поля",
      "missing_fields": missing_fields,
      "message": f"Необходимо заполнить: {', '.join(missing_fields)}"}, 400

    # 3. Проверка пустых значений
  empty_fields = []
  for field in required_fields:
    if not request_body[field] or not str(request_body[field]).strip():
      empty_fields.append(field)

  if empty_fields:
    return {
      "error": "Обязательные поля не могут быть пустыми",
      "empty_fields": empty_fields,
      "message": f"Заполните поля: {', '.join(empty_fields)}"}, 400

  email_input = request_body["email_input"].strip()
  pwd_input = request_body["pwd_input"].strip()

  email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
  if not re.match(email_regex, email_input):
    return {
      "error": "Некорректный формат email",
      "message": "Проверьте введенный email. Должен соответствовать виду: user@example.com"
                  }, 400

    # 6. Валидация пароля
  if len(pwd_input) < 8:
    return {
      "error": "Слишком короткий пароль",
      "message": "Проверьте введенный пароль. Пароль должен содержать минимум 8 символов"}, 400
#------------------
  request_body = request.get_json()
  auth_info = users_auth.objects().to_json()
  auth_info = json.loads(auth_info)
  auth_info = [
            {
                'user_email': user['user_email'],
                'pwd_hash': user['pwd_hash']
            }
            for user in auth_info]

  user_record = None
  for user in auth_info:
    if user['user_email'] == request_body['email_input']:
      user_record = user

  if not user_record:
    return {
        "error": "В системе нет зарегистрированного аккаунта с введенным email."
      }, 404

  # проверка пароля
  if str(hash(request_body['pwd_input'])) != user_record['pwd_hash']:
    return {
            "error": "Неверный пароль для указанного email."
            }, 401

  # заглушка, после будет интеграция с HRM-системой
  response = {"subdivision_list" : ['Отдел машинного обучения', 'Группа аналитики данных']}

  if response['subdivision_list'] == []:
    auth_role = 'employee'
  elif len(response['subdivision_list']) > 0:
    auth_role = 'manager'
  else:
    return {"error": "Ошибка сервера. Попробуйте повторить позже"}, 500

  session_info = sessions_info.objects().to_json()
  session_info = json.loads(session_info)
  session_info = [
            {
                'user_email': user['user_email']
            }
            for user in session_info]

  for user in session_info:
    if user['user_email'] == request_body['email_input']:
      token_record = True

  if token_record:
    token_session = secrets.token_urlsafe(32)
    try:
      sessions_info.objects(user_email = request_body['email_input']).update_one(set__token_session = token_session)
      sessions_info.objects(user_email = request_body['email_input']).update_one(set__expires_at = datetime.datetime.now() + datetime.timedelta(hours = 1))
    except Exception as e:
      return {"error": "Ошибка сервера. Попробуйте повторить позже"}, 500
  else:
    token_session = secrets.token_urlsafe(32)
    try:
      sessions_info(
                  token_session = token_session,
                  user_email = request_body['email_input'],
                  role = auth_role,
                  subdivision_list_session = response['subdivision_list'],
                  expires_at = datetime.datetime.now() + datetime.timedelta(hours = 1),
                  ).save()

    except Exception as e:
        return {"error": "Ошибка сервера. Попробуйте повторить позже"}, 500

  return {
    "message" : "Вы успешно авторизованы.",
    "user_email_auth" : request_body['email_input'] ,
    "system_role" : auth_role,
    "token_session" : token_session
   }, 200

#-----------------------------------------------------
# проверка авторизации
@app.route('/fte_records/signin/auth_check', methods=['POST'])
def sign_in_check():
  request_token = request.headers.get('Authorization')
  if not request_token:
    return {
  "error": "Отсутствует токен."
}, 401

  session_info = sessions_info.objects(token_session = request_token).to_json()
  if json.loads(session_info) == []:
    return {
      "error": "Авторизация не найдена в системе."
      }, 404

  if datetime.datetime.fromtimestamp(json.loads(session_info)[0]['expires_at']['$date']/1000) < datetime.datetime.now():
    return {
      "error": "Срок действия токена истек. Авторизуйтесь заново."
    }, 401

  return {
      "message": "Пользователь авторизован."
      }, 200

#-----------------------------------------------------
# получение мастер-справочника
@app.route('/fte_records/master_list', methods=['GET'])
def get_master_list():
  response = requests.post(
    f"{request.host_url}/fte_records/signin/auth_check", ### заменить на ссылку сервиса
    headers={'Authorization': request.headers.get('Authorization')}
)
  if response.status_code in [401, 404]:
    return {
      "error": response.json()['error']
      }, response.status_code

  session_info = sessions_info.objects(token_session = request.headers.get('Authorization')).to_json()
  session_info = json.loads(session_info)[0]

  # Сбор данных для каждого подразделения
  result = []

  for subdivision_name in session_info['subdivision_list_session']:
    # Получение tasks_list для каждого подразделения
    tasks_data = json.loads(tasks_master_list.objects(subdivision_name=subdivision_name).to_json())
    tasks_data = tasks_data[0]['tasks_list'] if tasks_data else {}


    result.append({
       "subdivision_name": subdivision_name,
       "tasks_json": tasks_data
        })

  return {
        "master_list": result
    }, 200

#-----------------------------------------------------
# редактирование задачи
@app.route('/fte_records/master_list/update', methods=['PATCH'])
def update_task_name():

  response = requests.post(
    f"{request.host_url}/fte_records/signin/auth_check", ### заменить на ссылку сервиса
    headers={'Authorization': request.headers.get('Authorization')})

  if response.status_code in [401, 404]:
    return {
      "error": response.json()['error']
      }, response.status_code


  request_body = request.get_json()

# 1. Проверка наличия тела запроса
  if not request_body:
    return {
      "error": "Тело запроса не может быть пустым"}, 400

  required_fields = ["task_id", "new_task_name"]
  missing_fields = [field for field in required_fields if field not in request_body]

  if missing_fields:
    return {
      "error": "Отсутствуют обязательные поля",
      "missing_fields": missing_fields,
      "message": f"Необходимо заполнить: {', '.join(missing_fields)}"}, 400

  # 3. Проверка пустых значений
  empty_fields = []
  for field in required_fields:
    if not request_body[field] or not str(request_body[field]).strip():
      empty_fields.append(field)

  if empty_fields:
    return {
      "error": "Обязательные поля не могут быть пустыми",
      "empty_fields": empty_fields,
      "message": f"Заполните поля: {', '.join(empty_fields)}"}, 400

  new_task_name = request_body["new_task_name"].strip()

  if len(new_task_name) < 2:
    return {
	    "error": "Некорректный формат new_task_name",
	    "message": "Проверьте new_task_name. Должно быть длиньше 2 символов."
        }, 400

  session_info = sessions_info.objects(token_session = request.headers.get('Authorization')).to_json()
  session_info = json.loads(session_info)[0]

  # Сбор данных для каждого подразделения
  result = []
  task_ids = []
  for subdivision_name in session_info['subdivision_list_session']:
    # Получение tasks_list для каждого подразделения
    tasks_data = json.loads(tasks_master_list.objects(subdivision_name=subdivision_name).to_json())
    tasks_data = tasks_data[0]['tasks_list'] if tasks_data else {}
    if tasks_data != {}:
      for key,value in tasks_data.items():
        task_ids.append(key)

  if not request_body["task_id"] in task_ids:
    return {
        "error" : "У вас нет доступа для редактирования названия задачи с указанным id."
          }, 403
  try:
    tasks_master_list.objects(
                  __raw__={f"tasks_list.{request_body['task_id']}": {"$exists": True}}
              ).update(
                  __raw__={"$set": {f"tasks_list.{request_body['task_id']}": request_body['new_task_name']}}
              )
  except Exception as e:
        return {"error": "Ошибка сервера. Попробуйте повторить позже"}, 500


  return {
      "message" : "Название задачи было успешно изменено."
      }, 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=False)