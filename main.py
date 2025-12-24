from fastapi import FastAPI, Depends, HTTPException
from typing import Annotated
import psycopg
import json
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, field_validator, Field, FutureDate
from passlib.hash import pbkdf2_sha256 as alg
import datetime

# loads data from another file for security
with open("../data.json", "r") as file:
    data = json.load(file)
    DB_PASSWORD = data["password"] #postgres superuser password
    TOKEN = data["token"] #token for fastapi authorization

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN)

# create tables if runs for first time
with psycopg.connect(f'dbname=task_tracker user=postgres password={DB_PASSWORD}') as conn:
    with conn.cursor() as cur:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
            id serial PRIMARY KEY,
            login varchar(20) NOT NULL,
            password varchar(20) NOT NULL
            )
            ''')
        cur.execute('''
                    CREATE TABLE IF NOT EXISTS tasks (
                    id serial PRIMARY KEY,
                    text varchar(256) NOT NULL,
                    date date NOT NULL,
                    is_done boolean NOT NULL,
                    user_id int NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                    ''')

# user data validation for registration. login must be unique. password > 8 symbols
class UserReg(BaseModel):
    login: str
    password: str = Field(min_length=8)

    @field_validator('login')
    @classmethod
    def login_unique(cls, login: str):
        with psycopg.connect(f'dbname=task_tracker user=postgres password={DB_PASSWORD}') as conn:
            with conn.cursor() as cur:
                user = cur.execute(f'SELECT id FROM users WHERE login = \'{login}\'').fetchone()
        if user:
            raise HTTPException(status_code=422, detail='User already exists')
        return login

# check add validation. requires task text, optional: data, tag. always creates as undone
class Task(BaseModel):
    text: str = Field(max_length=256)
    date: FutureDate = Field(default=datetime.date.today() + datetime.timedelta(days=1))
    tag: str = Field(default='')

# check if task with this id exists
class TaskID(BaseModel):
    id: int

    @field_validator('id')
    @classmethod
    def does_id_exist(cls, id: int):
        with psycopg.connect(f'dbname=task_tracker user=postgres password={DB_PASSWORD}') as conn:
            with conn.cursor() as cur:
                if not cur.execute(f'SELECT id FROM tasks WHERE id = \'{id}\'').fetchone():
                    raise HTTPException(status_code=404, detail='Task not found')

                return id


# registration. creates new user in DB. password is hashed
@app.post("/reg")
def reg(user : UserReg):
    with psycopg.connect(f'dbname=task_tracker user=postgres password={DB_PASSWORD}') as conn:
        with conn.cursor() as cur:
            cur.execute(f'INSERT INTO users (login, password) VALUES (\'{user.login}\', \'{alg.hash(user.password)}\')')

    return {"status": f"{user.login} registered"}

# add task. default values: date: tomorrow, tag: ''
@app.post("/add_task")
def add_task(task: Task, token: Annotated[str, Depends(oauth2_scheme)]):
    with psycopg.connect(f'dbname=task_tracker user=postgres password={DB_PASSWORD}') as conn:
        with conn.cursor() as cur:
            id = cur.execute(f'INSERT INTO tasks (text, date, user_id, is_done, tag) VALUES (\'{task.text}\', \'{task.date}\', {int(token)}, false, \'{task.tag}\') RETURNING id').fetchone()[0]

    return {'message': f'Task added! Task id: {id}'}

# get tasks. filters by user and tag
@app.get("/tasks")
def get_tasks(token: Annotated[str, Depends(oauth2_scheme)], tag: str=''):
    command = f'''
    SELECT tag, text, date, id FROM tasks WHERE user_id = {int(token)} AND is_done = false
    '''
    # if tag wasn't given, show all tasks, else choose tasks only with this tag
    if tag:
        command += f' AND tag = \'{tag}\''

    # get all tasks, sorted by date
    with psycopg.connect(f'dbname=task_tracker user=postgres password={DB_PASSWORD}') as conn:
        with conn.cursor() as cur:
            tasks = cur.execute(command + ' ORDER BY date ASC').fetchall()

    # sort tasks by tags
    task_structured = {}
    for task in tasks:
        # if task doesn't have tag
        if not task[0]:
            if not 'without tag' in task_structured.keys():
                task_structured['without tag'] = []
            task_structured['without tag'] += [{
                'id': task[3],
                'text': task[1],
                'until': task[2]
            }]
        # if task has tag
        else:
            if not task[0] in task_structured.keys():
                task_structured[task[0]] = []
            task_structured[task[0]] += [{
                'id': task[3],
                'text': task[1],
                'until': task[2]
            }]

    return task_structured

# mark task as done. task must be yours to mark it. you can't change task that doesn't exist
@app.put('/mark_done')
def mark_done(task_id: TaskID, token: Annotated[str, Depends(oauth2_scheme)]):
    with psycopg.connect(f'dbname=task_tracker user=postgres password={DB_PASSWORD}') as conn:
        with conn.cursor() as cur:
            task = cur.execute(f'''
            SELECT user_id, text FROM tasks WHERE id = {task_id.id}
            ''').fetchone()

            # if someone will try to change not his task
            if task[0] != int(token):
                raise HTTPException(status_code=422, detail='You can change only yours tasks')

            cur.execute(f'UPDATE tasks SET is_done = true WHERE id = {task_id.id}')

    return {'message': f'Task [{task[1]}] marked as done'}

# login configuration. token = user id in DB
@app.post("/token")
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    with psycopg.connect(f'dbname=task_tracker user=postgres password={DB_PASSWORD}') as conn:
        with conn.cursor() as cur:
            users = cur.execute(f'SELECT login FROM users').fetchall()

            if (form_data.username,) not in users:
                raise HTTPException(status_code=400, detail='User with this username doesn\'t exist')

            password = cur.execute(f'SELECT password FROM users WHERE login = \'{form_data.username}\'').fetchone()[0]
            if not alg.verify(form_data.password, password):
                raise HTTPException(status_code=422, detail='Incorrect password')

            token = cur.execute(f'SELECT id FROM users WHERE login = \'{form_data.username}\'').fetchone()[0]

    return {"username": form_data.username, "status": "logged", "access_token": token, 'token_type': 'bearer'}