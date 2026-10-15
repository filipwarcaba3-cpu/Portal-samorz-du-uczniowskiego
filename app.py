import os, secrets, io, time
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlsplit
from flask import Flask, request, session, redirect, url_for, render_template, flash, abort, g, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Text, LargeBinary, select, insert, update, delete, func

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(MAX_CONTENT_LENGTH=25*1024*1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE') == '1')
dburl = os.getenv('DATABASE_URL', 'sqlite:///portal.db')
if dburl.startswith(('postgres://', 'postgresql://')):
    dburl = 'postgresql+psycopg://' + dburl.split('://', 1)[1]
engine = create_engine(dburl, pool_pre_ping=True)
meta = MetaData()
users = Table('users', meta, Column('id', Integer, primary_key=True), Column('name', String(160)), Column('login', String(100), unique=True), Column('password', Text), Column('role', String(20)), Column('position', String(60)), Column('suspended', Integer, default=0), Column('color', String(20), default='#059669'), Column('version', Integer, default=0), Column('failures', Integer, default=0), Column('locked_until', Integer, default=0))
events = Table('events', meta, Column('id', Integer, primary_key=True), Column('title', String(200)), Column('date', String(16)), Column('body', Text), Column('author', Integer))
ideas = Table('ideas', meta, Column('id', Integer, primary_key=True), Column('author', Integer), Column('body', Text), Column('created', String(30)))
messages = Table('messages', meta, Column('id', Integer, primary_key=True), Column('sender', Integer), Column('recipient', Integer), Column('subject', String(200)), Column('body', Text), Column('created', String(30)))
files = Table('files', meta, Column('id', Integer, primary_key=True), Column('message', Integer), Column('name', String(255)), Column('data', LargeBinary))
changes = Table('portal_changes', meta, Column('name', String(100), primary_key=True))
deliveries = Table('message_recipients', meta, Column('message', Integer, primary_key=True), Column('recipient', Integer, primary_key=True))
rich_bodies = Table('message_formatting', meta, Column('message', Integer, primary_key=True), Column('html', Text))
meta.create_all(engine)
POSITIONS = ['Przewodniczący', 'V-ce przewodniczący', 'Skarbnik', 'Sekretarz']
ROLES = {'student': 'Uczestnik samorządu szkolnego', 'guardian': 'Opiekun samorządu', 'admin': 'Administrator'}
COLORS = ['#059669', '#2563eb', '#dc2626', '#d97706', '#db2777']
def now(): return datetime.now(ZoneInfo('Europe/Warsaw'))

class MessageHTML(HTMLParser):
    """Allow only document formatting; never accept executable markup."""
    allowed = {'p','div','br','b','strong','i','em','u','s','ul','ol','li','blockquote','h2','h3','a','table','thead','tbody','tr','th','td','hr'}
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.stack = []
    def handle_starttag(self, tag, attrs):
        if tag not in self.allowed: return
        attributes = ''
        if tag == 'a':
            href = dict(attrs).get('href', '')
            try: scheme = urlsplit(href).scheme.lower()
            except ValueError: scheme = ''
            if scheme in ('https','http','mailto'):
                attributes = ' href="' + escape(href, quote=True) + '" rel="noopener noreferrer"'
        if tag in ('p','div','h2','h3'):
            align = dict(attrs).get('align','')
            for class_name in dict(attrs).get('class','').split():
                if class_name in ('align-left','align-center','align-right'): align = class_name[6:]
            for declaration in dict(attrs).get('style','').split(';'):
                key, _, value = declaration.partition(':')
                if key.strip().lower() == 'text-align': align = value.strip().lower()
            if align in ('left','center','right'): attributes += ' class="align-' + align + '"'
        self.parts.append('<' + tag + attributes + '>')
        if tag not in ('br','hr'): self.stack.append(tag)
    def handle_endtag(self, tag):
        if tag in self.stack:
            while self.stack:
                current = self.stack.pop()
                self.parts.append('</' + current + '>')
                if current == tag: break
    def handle_data(self, data): self.parts.append(escape(data))
    def result(self):
        while self.stack: self.parts.append('</' + self.stack.pop() + '>')
        return ''.join(self.parts)

def clean_message_html(value):
    parser = MessageHTML()
    parser.feed(value)
    return parser.result()

def recipient_ids(message):
    ids = [r['recipient'] for r in rows(deliveries, deliveries.c.message == message['id'])]
    return ids or [message['recipient']]

def can_read_message(message):
    return g.user['id'] == message['sender'] or g.user['id'] in recipient_ids(message)
with engine.begin() as c:
    if not c.scalar(select(func.count()).select_from(users)):
        login, password = os.getenv('ADMIN_LOGIN'), os.getenv('ADMIN_PASSWORD')
        if login and password:
            if len(password) < 4: raise RuntimeError('ADMIN_PASSWORD musi mieć co najmniej 4 znaki')
            c.execute(insert(users).values(name='Administrator', login=login, password=generate_password_hash(password), role='admin', position='', suspended=0, color=COLORS[0], version=0, failures=0, locked_until=0))
    marker = 'v1_1_admin_credentials'
    if not c.scalar(select(changes.c.name).where(changes.c.name == marker)):
        existing = c.execute(select(users).where(users.c.login == 'admin')).mappings().first()
        if existing:
            c.execute(update(users).where(users.c.id == existing['id']).values(password=generate_password_hash('1234'), role='admin', suspended=0, version=(existing['version'] or 0)+1, failures=0, locked_until=0))
        else:
            c.execute(insert(users).values(name='Administrator', login='admin', password=generate_password_hash('1234'), role='admin', position='', suspended=0, color=COLORS[0], version=0, failures=0, locked_until=0))
        c.execute(insert(changes).values(name=marker))

def rows(table, condition=None):
    with engine.connect() as c:
        q = select(table)
        if condition is not None: q = q.where(condition)
        return [dict(r) for r in c.execute(q).mappings()]

def token():
    if 'csrf' not in session: session['csrf'] = secrets.token_urlsafe(32)
    return session['csrf']

@app.before_request
def guard():
    g.script_nonce = secrets.token_urlsafe(24)
    g.user = None
    if session.get('uid'):
        found = rows(users, users.c.id == session['uid'])
        if found and found[0]['version'] == session.get('version'): g.user = found[0]
        else: session.clear()
    if g.user and g.user['suspended'] and request.endpoint not in ('health', 'logout'):
        return render_template('suspended.html'), 403
    if request.method == 'POST' and not secrets.compare_digest(session.get('csrf', ''), request.form.get('csrf', '')):
        abort(400)
    if request.method == 'POST' and not session.get('csrf'): abort(400)

@app.context_processor
def context(): return dict(csrf=token, roles=ROLES, positions=POSITIONS, colors=COLORS)

@app.after_request
def headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'nonce-" + g.script_nonce + "'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response

def access(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapped(*a, **kw):
            if not g.user: return redirect(url_for('login'))
            if roles and g.user['role'] not in roles: abort(403)
            return fn(*a, **kw)
        return wrapped
    return deco

@app.get('/health')
def health(): return {'status': 'ok'}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        found = rows(users, users.c.login == request.form.get('login', '').strip())
        u = found[0] if found else None
        valid = check_password_hash(u['password'] if u else generate_password_hash('invalid'), request.form.get('password', ''))
        if u and (u['locked_until'] or 0) <= time.time() and valid:
            session.clear(); session.update(uid=u['id'], version=u['version'])
            with engine.begin() as c: c.execute(update(users).where(users.c.id == u['id']).values(failures=0, locked_until=0))
            return redirect('/')
        if u:
            failures = (u['failures'] or 0) + 1
            with engine.begin() as c: c.execute(update(users).where(users.c.id == u['id']).values(failures=failures, locked_until=int(time.time())+300 if failures >= 5 else 0))
        flash('Nieprawidłowe dane logowania lub konto czasowo zablokowane.')
    return render_template('login.html')

@app.post('/logout')
def logout(): session.clear(); return redirect('/login')

@app.get('/')
@access()
def home():
    return render_template('home.html', upcoming=sorted([e for e in rows(events) if e['date'] >= now().strftime('%Y-%m-%dT%H:%M')], key=lambda e:e['date'])[:4])

@app.route('/calendar', methods=['GET', 'POST'])
@access()
def calendar():
    if request.method == 'POST':
        if g.user['role'] not in ('guardian','admin'): abort(403)
        title, date = request.form.get('title','').strip(), request.form.get('date','')
        try: datetime.strptime(date, '%Y-%m-%dT%H:%M')
        except ValueError: abort(400)
        if not title: abort(400)
        with engine.begin() as c: c.execute(insert(events).values(title=title[:200],date=date,body=request.form.get('body','')[:10000],author=g.user['id']))
        return redirect('/calendar')
    return render_template('calendar.html', events=sorted(rows(events),key=lambda e:e['date']))

@app.post('/calendar/<int:eid>/delete')
@access('guardian','admin')
def delete_event(eid):
    with engine.begin() as c: c.execute(delete(events).where(events.c.id == eid))
    return redirect('/calendar')

@app.route('/ideas', methods=['GET','POST'])
@access()
def idea_box():
    if request.method == 'POST':
        body=request.form.get('body','').strip()
        if not body or len(body)>10000: abort(400)
        with engine.begin() as c: c.execute(insert(ideas).values(author=g.user['id'],body=body,created=now().strftime('%Y-%m-%dT%H:%M')))
        flash('Pomysł został opublikowany.'); return redirect('/ideas')
    return render_template('ideas.html', entries=rows(ideas)[::-1], names={u['id']:u['name'] for u in rows(users)}, editing=None)

@app.route('/ideas/<int:iid>/edit', methods=['GET','POST'])
@access()
def edit_idea(iid):
    found = rows(ideas, ideas.c.id == iid)
    if not found: abort(404)
    idea = found[0]
    if idea['author'] != g.user['id'] and g.user['role'] != 'admin': abort(403)
    if request.method == 'POST':
        body = request.form.get('body','').strip()
        if not body or len(body) > 10000: abort(400)
        with engine.begin() as c: c.execute(update(ideas).where(ideas.c.id == iid).values(body=body))
        flash('Pomysł został zaktualizowany.'); return redirect('/ideas')
    return render_template('ideas.html', entries=[], names={u['id']:u['name'] for u in rows(users)}, editing=idea)

@app.post('/ideas/<int:iid>/delete')
@access()
def delete_idea(iid):
    found = rows(ideas, ideas.c.id == iid)
    if not found: abort(404)
    if found[0]['author'] != g.user['id'] and g.user['role'] != 'admin': abort(403)
    with engine.begin() as c: c.execute(delete(ideas).where(ideas.c.id == iid))
    flash('Pomysł został usunięty.'); return redirect('/ideas')

@app.route('/mail', methods=['GET','POST'])
@access()
def mail():
    people=rows(users, users.c.id != g.user['id'])
    if request.method == 'POST':
        try: recipients=list(dict.fromkeys(int(uid) for uid in request.form.getlist('recipient')))
        except ValueError: abort(400)
        allowed = {u['id'] for u in people}
        if not recipients or any(uid not in allowed for uid in recipients): abort(400)
        subject=request.form.get('subject','').strip()
        if not subject or len(subject)>200: abort(400)
        uploads=[f for f in request.files.getlist('attachments') if f.filename]
        if len(uploads)>10: abort(400, 'Maksymalnie 10 załączników.')
        body = request.form.get('body','')
        html = request.form.get('body_html','')
        if len(body)>20000 or len(html)>100000: abort(400)
        with engine.begin() as c:
            mid=c.execute(insert(messages).values(sender=g.user['id'],recipient=recipients[0],subject=subject,body=body,created=now().strftime('%Y-%m-%dT%H:%M'))).inserted_primary_key[0]
            c.execute(insert(deliveries), [dict(message=mid,recipient=uid) for uid in recipients])
            if html: c.execute(insert(rich_bodies).values(message=mid,html=clean_message_html(html)))
            for f in uploads:
                name=f.filename.replace('\\','/').split('/')[-1][:255]
                c.execute(insert(files).values(message=mid,name=name,data=f.read()))
        flash('Wiadomość wysłana.'); return redirect('/mail?folder=sent')
    sent=request.args.get('folder')=='sent'
    inbox = (messages.c.recipient==g.user['id']) | messages.c.id.in_(select(deliveries.c.message).where(deliveries.c.recipient==g.user['id']))
    entries=rows(messages, messages.c.sender==g.user['id']) if sent else rows(messages,inbox)
    return render_template('mail.html',people=people,entries=entries[::-1],sent=sent,names={u['id']:u['name'] for u in rows(users)}, recipients={m['id']:recipient_ids(m) for m in entries})

@app.get('/mail/<int:mid>')
@access()
def message(mid):
    found=rows(messages,messages.c.id==mid)
    if not found: abort(404)
    m=found[0]
    if not can_read_message(m): abort(403)
    with engine.connect() as c:
        attachments=[dict(r) for r in c.execute(select(files.c.id,files.c.name).where(files.c.message==mid)).mappings()]
    formatted = rows(rich_bodies, rich_bodies.c.message == mid)
    html = clean_message_html(formatted[0]['html']) if formatted else None
    return render_template('message.html',m=m,attachments=attachments,names={u['id']:u['name'] for u in rows(users)}, recipients=recipient_ids(m), html=html)

@app.get('/attachments/<int:fid>')
@access()
def attachment(fid):
    found=rows(files,files.c.id==fid)
    if not found: abort(404)
    f=found[0]; m=rows(messages,messages.c.id==f['message'])
    if not m or not can_read_message(m[0]): abort(403)
    return send_file(io.BytesIO(f['data']),download_name=f['name'],as_attachment=True,mimetype='application/octet-stream')

@app.route('/users', methods=['GET','POST'])
@app.route('/team', methods=['GET','POST'])
@access('guardian','admin')
def management():
    isadmin=g.user['role']=='admin'
    if request.path=='/users' and not isadmin: abort(403)
    if request.method=='POST':
        action=request.form.get('action')
        if action=='create':
            role=request.form.get('role','student') if isadmin else 'student'
            if role not in ROLES: abort(400)
            position=request.form.get('position','') if role=='student' else ''
            if role=='student' and position not in POSITIONS: abort(400)
            name=request.form.get('name','').strip(); login=request.form.get('login','').strip(); password=request.form.get('password','')
            if not name or not login or len(name)>160 or len(login)>100 or len(password)<4:
                flash('Podaj imię i nazwisko, login i hasło co najmniej 4 znaki.'); return redirect(request.path)
            from sqlalchemy.exc import IntegrityError
            try:
                with engine.begin() as c: c.execute(insert(users).values(name=name,login=login,password=generate_password_hash(password),role=role,position=position,suspended=0,color=COLORS[0],version=0,failures=0,locked_until=0))
                flash('Konto zostało dodane.')
            except IntegrityError: flash('Ten login jest już zajęty.')
        else:
            try: uid=int(request.form.get('uid',''))
            except ValueError: abort(400)
            with engine.begin() as c:
                # Serializacja zmian kont administratorów chroni ostatnie aktywne konto.
                admins=list(c.execute(select(users).where(users.c.role=='admin').order_by(users.c.id).with_for_update()).mappings())
                target=c.execute(select(users).where(users.c.id==uid)).mappings().first()
                if not target: abort(404)
                if not isadmin and target['role']!='student': abort(403)
                if uid==g.user['id'] and action in ('delete','suspend'): abort(400,'Nie możesz usunąć ani zawiesić własnego konta.')
                if target['role']=='admin' and action in ('delete','suspend') and not target['suspended'] and sum(not a['suspended'] for a in admins)<=1: abort(400)
                if action=='delete':
                    if not isadmin: abort(403)
                    c.execute(delete(users).where(users.c.id==uid))
                elif action in ('suspend','resume'):
                    c.execute(update(users).where(users.c.id==uid).values(suspended=int(action=='suspend')))
                elif action=='password':
                    if not isadmin: abort(403)
                    password=request.form.get('password','')
                    if len(password)<4: flash('Hasło musi mieć co najmniej 4 znaki.'); return redirect(request.path)
                    c.execute(update(users).where(users.c.id==uid).values(password=generate_password_hash(password),version=target['version']+1,failures=0,locked_until=0))
                else: abort(400)
            flash('Zmiany zapisane.')
        return redirect(request.path)
    people=rows(users) if request.path=='/users' else rows(users,users.c.role=='student')
    return render_template('users.html',people=people,isadmin=isadmin)

@app.route('/profile',methods=['GET','POST'])
@access()
def profile():
    if request.method=='POST':
        color=request.form.get('color')
        if color not in COLORS: abort(400)
        values={'color':color}
        password=request.form.get('password','')
        if password:
            if len(password)<4 or not check_password_hash(g.user['password'],request.form.get('current_password','')):
                flash('Podaj poprawne obecne hasło i nowe hasło co najmniej 4 znaki.'); return redirect('/profile')
            values.update(password=generate_password_hash(password),version=g.user['version']+1)
        with engine.begin() as c: c.execute(update(users).where(users.c.id==g.user['id']).values(**values))
        if password: session['version']=values['version']
        flash('Profil zaktualizowany.'); return redirect('/profile')
    return render_template('profile.html')

@app.errorhandler(413)
def too_large(e): return render_template('error.html',message='Wiadomość wraz z załącznikami może mieć maksymalnie 25 MB.'),413

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def error(e): return render_template('error.html',message='Nie można wykonać tej operacji. Sprawdź dane i swoje uprawnienia.'),e.code

if __name__=='__main__': app.run(host='127.0.0.1',port=5000)
