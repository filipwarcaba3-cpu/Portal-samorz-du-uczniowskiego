import os, secrets, io, time, hmac, hashlib, unicodedata, json, mimetypes
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlsplit
from flask import Flask, request, session, redirect, url_for, render_template, flash, abort, g, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, BigInteger, String, Text, LargeBinary, UniqueConstraint, select, insert, update, delete, func, inspect
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(MAX_CONTENT_LENGTH=30*1024*1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE') == '1')
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
external_ideas = Table('external_ideas', meta, Column('id', Integer, primary_key=True), Column('name', String(160)), Column('school_class', String(60)), Column('body', Text), Column('created', String(30)))
idea_removals = Table('external_idea_removals', meta, Column('idea', Integer, primary_key=True), Column('requester', Integer), Column('created', String(30)))
vote_requests = Table('vote_requests', meta, Column('id', Integer, primary_key=True), Column('source_type', String(20), nullable=False), Column('source_id', Integer, nullable=False), Column('requester', Integer), Column('author_name', String(160)), Column('school_class', String(60)), Column('body', Text), Column('status', String(20), nullable=False, default='pending'), Column('poll_id', Integer), Column('created', String(30)), UniqueConstraint('source_type','source_id',name='uq_vote_request_source'))
polls = Table('polls', meta, Column('id', Integer, primary_key=True), Column('title', String(200), nullable=False), Column('created_by', Integer), Column('created', String(30)), Column('starts_at', String(40)), Column('ends_at', String(40)), Column('results_public', Integer, nullable=False, default=0, server_default='0'), Column('archived', Integer, nullable=False, default=0, server_default='0'))
poll_options = Table('poll_options', meta, Column('id', Integer, primary_key=True), Column('poll_id', Integer, nullable=False), Column('source_type', String(20)), Column('source_id', Integer), Column('author_name', String(160)), Column('school_class', String(60)), Column('body', Text, nullable=False), Column('created', String(30)))
poll_voters = Table('poll_voters', meta, Column('id', BigInteger, primary_key=True), Column('poll_id', Integer, nullable=False), Column('kind', String(20), nullable=False), Column('internal_user', Integer), Column('external_key', String(64)), Column('ballot_key', String(64), unique=True), Column('display_name', String(160)), Column('school_class', String(60)), Column('created', String(30)), Column('anonymized', Integer, default=0), UniqueConstraint('poll_id','internal_user',name='uq_poll_internal_voter'), UniqueConstraint('poll_id','external_key',name='uq_poll_external_voter'))
secret_ballots = Table('secret_ballots', meta, Column('id', BigInteger, primary_key=True), Column('ballot_key', String(64), unique=True, nullable=False), Column('poll_id', Integer, nullable=False), Column('option_id', Integer, nullable=False))
poll_voter_removals = Table('poll_voter_removals', meta, Column('voter_id', BigInteger, primary_key=True), Column('requester', Integer), Column('created', String(30)))
poll_internal_voter_removals = Table('poll_internal_voter_removals', meta, Column('voter_id', BigInteger, primary_key=True), Column('requester', Integer), Column('created', String(30)))
poll_deletion_requests = Table('poll_deletion_requests', meta, Column('poll_id', Integer, primary_key=True), Column('requester', Integer), Column('created', String(30)))
login_announcements = Table('login_announcements', meta, Column('id', Integer, primary_key=True), Column('title', String(160), nullable=False), Column('body', Text, nullable=False), Column('image_data', LargeBinary), Column('created', String(30)))
announcement_images = Table('announcement_images', meta, Column('id', Integer, primary_key=True), Column('announcement_id', Integer, nullable=False), Column('image_data', LargeBinary, nullable=False))
login_screen_images = Table('login_screen_images', meta, Column('id', Integer, primary_key=True), Column('image_data', LargeBinary, nullable=False), Column('mime_type', String(40), nullable=False))
chat_messages = Table('chat_messages', meta, Column('id', Integer, primary_key=True), Column('sender', Integer, nullable=False), Column('kind', String(20), nullable=False, default='text'), Column('body', Text, nullable=False, default=''), Column('created', String(30), nullable=False), Column('edited', Integer, nullable=False, default=0))
chat_attachments = Table('chat_attachments', meta, Column('id', Integer, primary_key=True), Column('message_id', Integer, nullable=False), Column('name', String(255), nullable=False), Column('mime_type', String(100), nullable=False), Column('data', LargeBinary, nullable=False))
chat_polls = Table('chat_polls', meta, Column('message_id', Integer, primary_key=True), Column('allow_multiple', Integer, nullable=False, default=0))
chat_poll_questions = Table('chat_poll_questions', meta, Column('id', Integer, primary_key=True), Column('message_id', Integer, nullable=False), Column('position', Integer, nullable=False), Column('body', String(500), nullable=False))
chat_poll_options = Table('chat_poll_options', meta, Column('id', Integer, primary_key=True), Column('question_id', Integer, nullable=False), Column('position', Integer, nullable=False), Column('body', String(200), nullable=False))
chat_poll_votes = Table('chat_poll_votes', meta, Column('id', Integer, primary_key=True), Column('question_id', Integer, nullable=False), Column('option_id', Integer, nullable=False), Column('voter_id', Integer, nullable=False), UniqueConstraint('question_id','voter_id','option_id',name='uq_chat_vote_choice'))
portal_settings = Table('portal_settings', meta, Column('key', String(100), primary_key=True), Column('value', Text, nullable=False))
meta.create_all(engine)
if 'results_public' not in {column['name'] for column in inspect(engine).get_columns('polls')}:
    try:
        with engine.begin() as c:
            c.exec_driver_sql("ALTER TABLE polls ADD COLUMN results_public INTEGER NOT NULL DEFAULT 0")
    except Exception:
        # Multiple Render workers may try the one-time migration at startup.
        if 'results_public' not in {column['name'] for column in inspect(engine).get_columns('polls')}:
            raise
if 'archived' not in {column['name'] for column in inspect(engine).get_columns('polls')}:
    try:
        with engine.begin() as c:
            c.exec_driver_sql("ALTER TABLE polls ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
    except Exception:
        # Multiple Render workers may try the one-time migration at startup.
        if 'archived' not in {column['name'] for column in inspect(engine).get_columns('polls')}:
            raise
try:
    with engine.begin() as c:
        if not c.scalar(select(portal_settings.c.key).where(portal_settings.c.key=='external_voter_hash_secret')):
            c.execute(insert(portal_settings).values(key='external_voter_hash_secret',value=secrets.token_hex(32)))
except IntegrityError:
    # Another web worker may initialize the same setting at the same time.
    pass
with engine.connect() as c:
    VOTER_HASH_SECRET = c.scalar(select(portal_settings.c.value).where(portal_settings.c.key=='external_voter_hash_secret'))
POSITIONS = ['Przewodniczący', 'V-ce przewodniczący', 'Skarbnik', 'Sekretarz']
ROLES = {'student': 'Uczestnik samorządu szkolnego', 'guardian': 'Opiekun samorządu', 'admin': 'Administrator'}
COLORS = ['#059669', '#2563eb', '#dc2626', '#d97706', '#db2777']
def now(): return datetime.now(ZoneInfo('Europe/Warsaw'))

def poll_state(poll):
    if not poll['starts_at'] or not poll['ends_at']: return 'draft'
    current = now()
    start = datetime.fromisoformat(poll['starts_at'])
    end = datetime.fromisoformat(poll['ends_at'])
    if current < start: return 'scheduled'
    if current < end: return 'open'
    return 'closed'

def local_datetime(value):
    try: return datetime.strptime(value, '%Y-%m-%dT%H:%M').replace(tzinfo=ZoneInfo('Europe/Warsaw'))
    except (TypeError, ValueError): abort(400)

def external_voter_key(name):
    normalized = ' '.join(unicodedata.normalize('NFKC', name).casefold().split())
    return hmac.new(VOTER_HASH_SECRET.encode('utf-8'), normalized.encode('utf-8'), hashlib.sha256).hexdigest()

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

LOGIN_SCREEN_DEFAULTS = {
    'info_title': 'Zespół Szkół Muzycznych',
    'info_body': 'im. Michała Spisaka w Dąbrowie Górniczej\nhttps://www.gov.pl/web/zsmdabrowa',
    'ideas_title': 'Skrzynka pomysłów',
    'ideas_body': 'Masz pomysł dla naszej szkoły? Przekaż go samorządowi bez logowania.',
    'voting_title': 'Głosowania',
    'voting_body': 'Możesz oddać głos także bez logowania.',
    'results_title': 'Wyniki głosowań',
    'results_body': 'Zobacz wyniki udostępnione przez opiekunów samorządu.'
}

LOGIN_LAYOUT_DEFAULTS = {
    'login': {'columns': 7, 'rows': 2, 'order': 0},
    'announcements': {'columns': 5, 'rows': 1, 'order': 1},
    'ideas': {'columns': 5, 'rows': 1, 'order': 2},
    'voting': {'columns': 5, 'rows': 1, 'order': 3},
    'results': {'columns': 5, 'rows': 1, 'order': 4},
}

def normalize_login_layout(value):
    """Return only safe, bounded layout values for public CSS grid placement."""
    if isinstance(value, str):
        try: value = json.loads(value)
        except (TypeError, ValueError): value = None
    if not isinstance(value, dict): return {key: dict(item) for key, item in LOGIN_LAYOUT_DEFAULTS.items()}
    normalized = {}
    for key, defaults in LOGIN_LAYOUT_DEFAULTS.items():
        item = value.get(key, {})
        if not isinstance(item, dict): item = {}
        parsed = {}
        for field, low, high in (('columns', 3, 12), ('rows', 1, 5), ('order', 0, 4)):
            try: number = int(item.get(field, defaults[field]))
            except (TypeError, ValueError): number = defaults[field]
            parsed[field] = max(low, min(high, number))
        normalized[key] = parsed
    return normalized

def login_screen_values():
    values = dict(LOGIN_SCREEN_DEFAULTS)
    prefix = 'login_screen_'
    for setting in rows(portal_settings):
        if setting['key'].startswith(prefix):
            key = setting['key'][len(prefix):]
            if key in values: values[key] = setting['value']
            elif key == 'layout': values['layout'] = normalize_login_layout(setting['value'])
    values['layout'] = normalize_login_layout(values.get('layout'))
    return values

def published_results():
    result = []
    for poll in sorted(rows(polls, (polls.c.results_public == 1) & (polls.c.archived == 0)), key=lambda p:p['id'], reverse=True):
        if poll_state(poll) != 'closed': continue
        options = rows(poll_options, poll_options.c.poll_id == poll['id'])
        ballots = rows(secret_ballots, secret_ballots.c.poll_id == poll['id'])
        counts = [dict(option, votes=sum(ballot['option_id'] == option['id'] for ballot in ballots)) for option in options]
        result.append(dict(poll=poll, options=counts, total=sum(option['votes'] for option in counts)))
    return result

def announcement_image_list(announcement):
    images=[]
    if announcement.get('has_legacy_image'):
        images.append({'url':f"/login-announcements/{announcement['id']}/image"})
    for image in sorted(rows(announcement_images, announcement_images.c.announcement_id==announcement['id']),key=lambda item:item['id']):
        images.append({'url':f"/login-announcements/{announcement['id']}/images/{image['id']}"})
    return images

def render_login_page(**extra):
    with engine.connect() as c:
        announcements = [dict(r) for r in c.execute(select(login_announcements.c.id, login_announcements.c.title, login_announcements.c.body, login_announcements.c.created, login_announcements.c.image_data.is_not(None).label('has_legacy_image')).order_by(login_announcements.c.id.desc())).mappings()]
    for announcement in announcements: announcement['images']=announcement_image_list(announcement)
    values = dict(screen=login_screen_values(), announcements=announcements, public_results=published_results())
    values.update(extra)
    return render_template('login.html', **values)

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
    return render_login_page()

@app.post('/logout')
def logout(): session.clear(); return redirect('/login')

@app.post('/external-ideas')
def submit_external_idea():
    values = {key: request.form.get(key,'').strip() for key in ('name','school_class','body')}
    if not all(values.values()):
        return render_login_page(external_values=values, external_error='Uzupełnij wszystkie trzy pola.', show_external_form=True), 400
    if len(values['name'])>160 or len(values['school_class'])>60 or len(values['body'])>10000:
        return render_login_page(external_values=values, external_error='Imię i nazwisko: do 160 znaków; klasa: do 60; pomysł: do 10 000.', show_external_form=True), 400
    with engine.begin() as c:
        c.execute(insert(external_ideas).values(**values, created=now().strftime('%Y-%m-%dT%H:%M')))
    flash('Twój pomysł został wysłany do skrzynki pomysłów samorządu. Dziękujemy!', 'success')
    return redirect('/login')

def jpeg_dimensions(data):
    offset=2
    frame_markers={0xC0,0xC1,0xC2,0xC3,0xC5,0xC6,0xC7,0xC9,0xCA,0xCB,0xCD,0xCE,0xCF}
    while offset+4<=len(data):
        if data[offset]!=0xFF:
            offset+=1
            continue
        while offset<len(data) and data[offset]==0xFF: offset+=1
        if offset>=len(data): break
        marker=data[offset]
        offset+=1
        if marker in (0xD8,0xD9,0x01) or 0xD0<=marker<=0xD7: continue
        if offset+2>len(data): break
        segment_length=int.from_bytes(data[offset:offset+2],'big')
        if segment_length<2 or offset+segment_length>len(data): break
        if marker in frame_markers and segment_length>=7:
            height=int.from_bytes(data[offset+3:offset+5],'big')
            width=int.from_bytes(data[offset+5:offset+7],'big')
            return width,height
        if marker==0xDA: break
        offset+=segment_length
    return None

def read_login_screen_upload():
    upload=request.files.get('logo_image')
    if not upload or not upload.filename: return None
    data=upload.stream.read(5*1024*1024+1)
    if len(data)>5*1024*1024: raise ValueError('Zdjęcie może mieć maksymalnie 5 MB.')
    if data.startswith(b'\x89PNG\r\n\x1a\n') and len(data)>=24 and data[12:16]==b'IHDR':
        mime_type='image/png'
        width=int.from_bytes(data[16:20],'big')
        height=int.from_bytes(data[20:24],'big')
    elif data.startswith(b'\xff\xd8\xff'):
        dimensions=jpeg_dimensions(data)
        if not dimensions: raise ValueError('Nie udało się odczytać wymiarów zdjęcia JPEG.')
        width,height=dimensions
        mime_type='image/jpeg'
    else:
        raise ValueError('Wybierz obraz PNG lub JPG.')
    if not width or not height or width*height>25_000_000:
        raise ValueError('Zdjęcie ma nieprawidłowe lub zbyt duże wymiary.')
    return data,mime_type

@app.route('/admin/login-screen', methods=['GET','POST'])
@access('admin')
def manage_login_screen():
    if request.method == 'POST':
        values = {key:request.form.get(key,'').strip() for key in LOGIN_SCREEN_DEFAULTS}
        try:
            layout_data = json.loads(request.form.get('layout', '{}'))
            layout = normalize_login_layout(layout_data)
            if not isinstance(layout_data, dict) or any(not isinstance(layout_data.get(key), dict) for key in LOGIN_LAYOUT_DEFAULTS):
                raise ValueError('Nieprawidłowy układ elementów.')
            for key, bounds in LOGIN_LAYOUT_DEFAULTS.items():
                for field, low, high in (('columns', 3, 12), ('rows', 1, 5), ('order', 0, 4)):
                    raw = layout_data[key].get(field)
                    if isinstance(raw, bool) or not isinstance(raw, int) or not low <= raw <= high:
                        raise ValueError('Sprawdź położenie i rozmiar elementów.')
            if len({item['order'] for item in layout.values()}) != len(layout):
                raise ValueError('Kolejność elementów jest nieprawidłowa.')
        except (TypeError, ValueError):
            flash('Nie udało się odczytać układu ekranu. Spróbuj ponownie.', 'error')
            return render_template('login_screen_admin.html', screen=login_screen_values()), 400
        limits = {'info_title':160,'info_body':1000,'ideas_title':100,'ideas_body':500,'voting_title':100,'voting_body':500,'results_title':100,'results_body':500}
        if any(not values[key] or len(values[key]) > limit for key,limit in limits.items()):
            flash('Uzupełnij wszystkie pola i sprawdź ich długość.', 'error')
            values['layout'] = layout
            return render_template('login_screen_admin.html', screen=values), 400
        try:
            logo_upload=read_login_screen_upload()
        except ValueError as error:
            flash(str(error), 'error')
            values['layout']=layout
            return render_template('login_screen_admin.html', screen=values), 400
        else:
            with engine.begin() as c:
                for key,value in values.items():
                    setting_key='login_screen_'+key
                    exists=c.scalar(select(portal_settings.c.key).where(portal_settings.c.key==setting_key))
                    if exists: c.execute(update(portal_settings).where(portal_settings.c.key==setting_key).values(value=value))
                    else: c.execute(insert(portal_settings).values(key=setting_key,value=value))
                layout_key='login_screen_layout'
                layout_value=json.dumps(layout, separators=(',', ':'))
                if c.scalar(select(portal_settings.c.key).where(portal_settings.c.key==layout_key)):
                    c.execute(update(portal_settings).where(portal_settings.c.key==layout_key).values(value=layout_value))
                else:
                    c.execute(insert(portal_settings).values(key=layout_key,value=layout_value))
                if logo_upload:
                    image_data,mime_type=logo_upload
                    if c.scalar(select(login_screen_images.c.id).where(login_screen_images.c.id==1)):
                        c.execute(update(login_screen_images).where(login_screen_images.c.id==1).values(image_data=image_data,mime_type=mime_type))
                    else:
                        c.execute(insert(login_screen_images).values(id=1,image_data=image_data,mime_type=mime_type))
                elif request.form.get('reset_logo')=='1':
                    c.execute(delete(login_screen_images).where(login_screen_images.c.id==1))
            flash('Zapisano treść publicznego ekranu logowania.', 'success')
            return redirect('/admin/login-screen')
    return render_template('login_screen_admin.html', screen=login_screen_values())

@app.get('/login-screen-logo')
def login_screen_logo():
    found=rows(login_screen_images, login_screen_images.c.id==1)
    if found:
        response=send_file(io.BytesIO(found[0]['image_data']),mimetype=found[0]['mime_type'],as_attachment=False,conditional=False)
    else:
        response=send_file(os.path.join(app.root_path,'static','school_logo.png'),mimetype='image/png',as_attachment=False,conditional=False)
    response.headers['Content-Disposition']='inline'
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    return response

def read_announcement_pngs():
    uploads=[upload for upload in request.files.getlist('images') if upload and upload.filename]
    if len(uploads)>5: raise ValueError('Do jednego ogłoszenia można dodać maksymalnie 5 obrazów.')
    images=[]
    for upload in uploads:
        data=upload.stream.read(5*1024*1024+1)
        if len(data)>5*1024*1024: raise ValueError('Każdy obraz PNG może mieć maksymalnie 5 MB.')
        if len(data)<24 or not data.startswith(b'\x89PNG\r\n\x1a\n') or data[12:16]!=b'IHDR':
            raise ValueError('Wszystkie załączniki muszą być poprawnymi obrazami PNG.')
        width=int.from_bytes(data[16:20],'big')
        height=int.from_bytes(data[20:24],'big')
        if not width or not height or width*height>25_000_000:
            raise ValueError('Obraz PNG ma nieprawidłowe lub zbyt duże wymiary.')
        images.append(data)
    return images

@app.route('/announcements', methods=['GET','POST'])
@access('guardian','admin')
def manage_announcements():
    if request.method == 'POST':
        action=request.form.get('action','create')
        try:
            if action == 'delete':
                announcement_id=int(request.form.get('announcement_id',''))
                with engine.begin() as c:
                    c.execute(delete(announcement_images).where(announcement_images.c.announcement_id==announcement_id))
                    removed=c.execute(delete(login_announcements).where(login_announcements.c.id==announcement_id))
                    if not removed.rowcount: abort(404)
                flash('Usunięto ogłoszenie.', 'success')
            elif action in ('create','edit'):
                title=request.form.get('title','').strip()
                body=request.form.get('body','').strip()
                if not title or len(title)>160 or not body or len(body)>10000: raise ValueError('Wpisz tytuł (maks. 160 znaków) i treść (maks. 10 000 znaków).')
                images=read_announcement_pngs()
                with engine.begin() as c:
                    if action=='create':
                        announcement_id=c.execute(insert(login_announcements).values(title=title,body=body,created=now().isoformat(timespec='minutes'))).inserted_primary_key[0]
                        for image in images:
                            c.execute(insert(announcement_images).values(announcement_id=announcement_id,image_data=image))
                    else:
                        announcement_id=int(request.form.get('announcement_id',''))
                        record=c.execute(select(login_announcements).where(login_announcements.c.id==announcement_id).with_for_update()).mappings().first()
                        if not record: abort(404)
                        values={'title':title,'body':body}
                        remove_images=request.form.get('remove_images')=='1'
                        current_count=0 if remove_images else (c.scalar(select(func.count()).select_from(announcement_images).where(announcement_images.c.announcement_id==announcement_id)) or 0) + (1 if record['image_data'] else 0)
                        if remove_images: values['image_data']=None
                        if current_count+len(images)>5: raise ValueError('Ogłoszenie może mieć maksymalnie 5 obrazów. Usuń obecne obrazy albo dodaj mniej plików.')
                        c.execute(update(login_announcements).where(login_announcements.c.id==announcement_id).values(**values))
                        if remove_images: c.execute(delete(announcement_images).where(announcement_images.c.announcement_id==announcement_id))
                        for image in images:
                            c.execute(insert(announcement_images).values(announcement_id=announcement_id,image_data=image))
                flash('Zapisano ogłoszenie.', 'success')
            else: abort(400)
        except ValueError as error:
            flash(str(error), 'error')
        return redirect('/announcements')
    with engine.connect() as c:
        announcements=[dict(r) for r in c.execute(select(login_announcements.c.id,login_announcements.c.title,login_announcements.c.body,login_announcements.c.created,login_announcements.c.image_data.is_not(None).label('has_legacy_image')).order_by(login_announcements.c.id.desc())).mappings()]
    for announcement in announcements: announcement['images']=announcement_image_list(announcement)
    return render_template('announcements.html', announcements=announcements)

@app.get('/login-announcements/<int:announcement_id>/image')
def login_announcement_image(announcement_id):
    found=rows(login_announcements, login_announcements.c.id==announcement_id)
    if not found or not found[0]['image_data']: abort(404)
    response=send_file(io.BytesIO(found[0]['image_data']),mimetype='image/png',as_attachment=False,conditional=False)
    response.headers['Content-Disposition']='inline'
    response.headers['Cache-Control']='no-store'
    return response

@app.get('/login-announcements/<int:announcement_id>/images/<int:image_id>')
def login_announcement_extra_image(announcement_id, image_id):
    found=rows(announcement_images, (announcement_images.c.id==image_id) & (announcement_images.c.announcement_id==announcement_id))
    if not found: abort(404)
    response=send_file(io.BytesIO(found[0]['image_data']),mimetype='image/png',as_attachment=False,conditional=False)
    response.headers['Content-Disposition']='inline'
    response.headers['Cache-Control']='no-store'
    return response

@app.post('/external-ideas/<int:iid>/delete')
@access()
def remove_external_idea(iid):
    with engine.begin() as c:
        idea = c.execute(select(external_ideas).where(external_ideas.c.id==iid).with_for_update()).mappings().first()
        if not idea: abort(404)
        if g.user['role'] in ('guardian','admin'):
            c.execute(delete(idea_removals).where(idea_removals.c.idea==iid))
            c.execute(delete(external_ideas).where(external_ideas.c.id==iid))
            flash('Pomysł zewnętrzny został usunięty.')
        else:
            pending = c.scalar(select(idea_removals.c.idea).where(idea_removals.c.idea==iid))
            if not pending:
                c.execute(insert(idea_removals).values(idea=iid,requester=g.user['id'],created=now().strftime('%Y-%m-%dT%H:%M')))
            flash('Prośba o usunięcie czeka na zatwierdzenie opiekuna. Pomysł pozostaje widoczny.')
    return redirect('/ideas')

@app.post('/external-ideas/<int:iid>/decision')
@access('guardian','admin')
def decide_external_removal(iid):
    decision = request.form.get('decision')
    if decision not in ('approve','reject'): abort(400)
    with engine.begin() as c:
        idea = c.execute(select(external_ideas).where(external_ideas.c.id==iid).with_for_update()).mappings().first()
        if not idea: abort(404)
        pending = c.scalar(select(idea_removals.c.idea).where(idea_removals.c.idea==iid))
        if not pending: abort(404)
        c.execute(delete(idea_removals).where(idea_removals.c.idea==iid))
        if decision == 'approve': c.execute(delete(external_ideas).where(external_ideas.c.id==iid))
    flash('Usunięcie pomysłu zostało zatwierdzone.' if decision=='approve' else 'Prośba została odrzucona. Pomysł pozostaje w skrzynce.')
    return redirect('/ideas')

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
    request_rows=rows(vote_requests)
    approved_sources={(r['source_type'],r['source_id']) for r in request_rows if r['status']=='approved'}
    draft_polls=[p for p in sorted(rows(polls, polls.c.archived==0),key=lambda item:item['id'],reverse=True) if poll_state(p)=='draft']
    return render_template('ideas.html', entries=[e for e in rows(ideas)[::-1] if ('internal',e['id']) not in approved_sources], names={u['id']:u['name'] for u in rows(users)}, editing=None, external_entries=[e for e in rows(external_ideas)[::-1] if ('external',e['id']) not in approved_sources], pending_removals={r['idea']:r for r in rows(idea_removals)}, vote_request_status={(r['source_type'],r['source_id']):r for r in request_rows}, draft_polls=draft_polls)

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
    return render_template('ideas.html', entries=[], names={u['id']:u['name'] for u in rows(users)}, editing=idea, vote_request_status={})

@app.post('/ideas/<int:iid>/delete')
@access()
def delete_idea(iid):
    found = rows(ideas, ideas.c.id == iid)
    if not found: abort(404)
    if found[0]['author'] != g.user['id'] and g.user['role'] != 'admin': abort(403)
    with engine.begin() as c: c.execute(delete(ideas).where(ideas.c.id == iid))
    flash('Pomysł został usunięty.'); return redirect('/ideas')

@app.post('/ideas/<source_type>/<int:item_id>/nominate')
@access('student','guardian','admin')
def nominate_idea(source_type, item_id):
    if source_type == 'internal':
        found = rows(ideas, ideas.c.id == item_id)
        if not found: abort(404)
        idea = found[0]
        author = rows(users, users.c.id == idea['author'])
        name, school_class, body = (author[0]['name'] if author else 'Usunięte konto'), '', idea['body']
    elif source_type == 'external':
        found = rows(external_ideas, external_ideas.c.id == item_id)
        if not found: abort(404)
        idea = found[0]
        name, school_class, body = idea['name'], idea['school_class'], idea['body']
    else: abort(404)
    direct=g.user['role'] in ('guardian','admin')
    values = dict(requester=g.user['id'], author_name=name[:160], school_class=school_class[:60], body=body[:10000], status='approved' if direct else 'pending', poll_id=None, created=now().isoformat(timespec='minutes'))
    with engine.begin() as c:
        prior = c.execute(select(vote_requests).where(vote_requests.c.source_type==source_type, vote_requests.c.source_id==item_id).with_for_update()).mappings().first()
        if direct and prior and prior['status']=='approved':
            flash('Ten pomysł jest już dodany do głosowania.')
        elif direct:
            poll_id=request.form.get('poll_id','').strip()
            title=request.form.get('new_poll_title','').strip()
            if bool(poll_id)==bool(title): abort(400)
            if title:
                if len(title)>200: abort(400)
                poll_id=c.execute(insert(polls).values(title=title,created_by=g.user['id'],created=now().isoformat(timespec='minutes'),starts_at=None,ends_at=None)).inserted_primary_key[0]
            else:
                try: poll_id=int(poll_id)
                except ValueError: abort(400)
                target=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
                if not target or target['archived'] or poll_state(target)!='draft': abort(400, 'Wybierz głosowanie, które jest jeszcze w przygotowaniu.')
            c.execute(insert(poll_options).values(poll_id=poll_id,source_type=source_type,source_id=item_id,author_name=name[:160],school_class=school_class[:60],body=body[:10000],created=now().isoformat(timespec='minutes')))
            values['poll_id']=poll_id
            if prior: c.execute(update(vote_requests).where(vote_requests.c.id==prior['id']).values(**values))
            else: c.execute(insert(vote_requests).values(source_type=source_type,source_id=item_id,**values))
            flash('Pomysł dodano bezpośrednio do głosowania.', 'success')
        elif prior and prior['status'] in ('pending','approved'):
            flash('Ten pomysł został już zgłoszony do głosowania.' if prior['status']=='pending' else 'Ten pomysł jest już dodany do głosowania.')
        elif prior:
            c.execute(update(vote_requests).where(vote_requests.c.id==prior['id']).values(**values))
            flash('Pomysł ponownie czeka na zatwierdzenie opiekuna.', 'success')
        else:
            c.execute(insert(vote_requests).values(source_type=source_type,source_id=item_id,**values))
            flash('Pomysł wysłano do opiekuna z prośbą o dodanie do głosowania.', 'success')
    return redirect('/ideas')

def voting_page_data(tab, selected_id=None):
    people = {u['id']:u['name'] for u in rows(users)}
    poll_rows = sorted(rows(polls, polls.c.archived == 0), key=lambda p:p['id'], reverse=True)
    deletion_requests = rows(poll_deletion_requests)
    titles = {poll['id']:poll['title'] for poll in poll_rows}
    deletion_by_poll = {item['poll_id']:dict(item, requester_name=people.get(item['requester'],'Usunięte konto'),title=titles.get(item['poll_id'],'Głosowanie')) for item in deletion_requests}
    enriched = []
    for poll in poll_rows:
        item = dict(poll)
        item['state'] = poll_state(poll)
        item['options'] = rows(poll_options, poll_options.c.poll_id==poll['id'])
        item['already_voted'] = bool(rows(poll_voters, (poll_voters.c.poll_id==poll['id']) & (poll_voters.c.internal_user==g.user['id'])))
        item['deletion_request'] = deletion_by_poll.get(poll['id'])
        enriched.append(item)
    pending = [dict(r, requester_name=people.get(r['requester'],'Usunięte konto')) for r in rows(vote_requests, vote_requests.c.status=='pending')]
    pending.sort(key=lambda r:r['created'] or '', reverse=True)
    active = [p for p in enriched if p['state'] in ('scheduled','open')]
    finished = [p for p in enriched if p['state']=='closed']
    selected = next((p for p in enriched if p['id']==selected_id), None)
    detail = None
    active_external_voters=[]
    if selected and selected['state'] in ('scheduled','open'):
        voter_rows=rows(poll_voters,poll_voters.c.poll_id==selected['id'])
        removals={r['voter_id']:r for r in rows(poll_voter_removals)}
        active_external_voters=[dict(v,removal=removals.get(v['id'])) for v in voter_rows if v['kind']=='external' and not v['anonymized']]
        active_external_voters.sort(key=lambda v:v['display_name'] or '')
    if selected and selected['state']=='closed':
        voter_rows = rows(poll_voters, poll_voters.c.poll_id==selected['id'])
        ballots = rows(secret_ballots, secret_ballots.c.poll_id==selected['id'])
        options = []
        for option in selected['options']:
            options.append(dict(option, votes=sum(b['option_id']==option['id'] for b in ballots)))
        removals = {r['voter_id']:r for r in rows(poll_voter_removals)}
        internal_removals={r['voter_id']:r for r in rows(poll_internal_voter_removals)}
        user_roles={u['id']:u['role'] for u in rows(users)}
        voters_internal = [dict(v,removal=internal_removals.get(v['id']),role=user_roles.get(v['internal_user'])) for v in voter_rows if v['kind']=='internal' and not v['anonymized']]
        voters_external = [dict(v, removal=removals.get(v['id'])) for v in voter_rows if v['kind']=='external' and not v['anonymized']]
        voters_internal.sort(key=lambda v:v['display_name'] or '')
        voters_external.sort(key=lambda v:v['display_name'] or '')
        detail = dict(poll=selected, options=options, internal_voters=voters_internal, external_voters=voters_external)
    external_voter_requests=[]
    if g.user['role'] in ('guardian','admin'):
        all_voters={v['id']:v for v in rows(poll_voters)}
        all_poll_rows=rows(polls)
        all_poll_titles={p['id']:p['title'] for p in all_poll_rows}
        for item in rows(poll_voter_removals):
            voter=all_voters.get(item['voter_id'])
            poll_title=all_poll_titles.get(voter['poll_id']) if voter else None
            if voter and voter['kind']=='external' and not voter['anonymized'] and poll_title:
                external_voter_requests.append(dict(item,voter_name=voter['display_name'] or 'Głosujący zewnętrzny',school_class=voter['school_class'],poll_title=poll_title,poll_id=voter['poll_id'],requester_name=people.get(item['requester'],'Użytkownik')))
        external_voter_requests.sort(key=lambda item:item['created'] or '',reverse=True)
    internal_voter_requests=[]
    if g.user['role']=='admin':
        user_names={u['id']:u['name'] for u in rows(users)}
        poll_titles={p['id']:p['title'] for p in poll_rows}
        all_voters={v['id']:v for v in rows(poll_voters)}
        for item in rows(poll_internal_voter_removals):
            voter=all_voters.get(item['voter_id'])
            if voter and (voter['kind']!='internal' or voter['anonymized']): voter=None
            if voter:
                internal_voter_requests.append(dict(item,voter_name=voter['display_name'] or 'Uczestnik',requester_name=user_names.get(item['requester'],'Usunięte konto'),poll_title=poll_titles.get(voter['poll_id'],'Głosowanie'),poll_id=voter['poll_id']))
    internal_voter_requests.sort(key=lambda item:item['created'] or '',reverse=True)
    return dict(tab=tab, pending_requests=pending, all_polls=enriched, draft_polls=[p for p in enriched if p['state']=='draft'], active_polls=active, finished_polls=finished, selected_poll=selected, detail=detail, active_external_voters=active_external_voters, people=people, deletion_requests=[deletion_by_poll[p['id']] for p in enriched if p['id'] in deletion_by_poll], internal_voter_requests=internal_voter_requests, external_voter_requests=external_voter_requests)

def delete_unstarted_poll(c, poll_id):
    poll=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
    if not poll: abort(404)
    if poll['archived'] or poll_state(poll) not in ('draft','scheduled'): abort(400, 'Można usuwać tylko nie rozpoczęte głosowania.')
    options=[dict(r) for r in c.execute(select(poll_options).where(poll_options.c.poll_id==poll_id)).mappings()]
    for option in options:
        if option['source_type'] in ('internal','external') and option['source_id']:
            c.execute(update(vote_requests).where(vote_requests.c.source_type==option['source_type'],vote_requests.c.source_id==option['source_id'],vote_requests.c.poll_id==poll_id).values(status='pending',poll_id=None))
    voter_ids=[r['id'] for r in c.execute(select(poll_voters.c.id).where(poll_voters.c.poll_id==poll_id)).mappings()]
    if voter_ids: c.execute(delete(poll_voter_removals).where(poll_voter_removals.c.voter_id.in_(voter_ids)))
    if voter_ids: c.execute(delete(poll_internal_voter_removals).where(poll_internal_voter_removals.c.voter_id.in_(voter_ids)))
    c.execute(delete(secret_ballots).where(secret_ballots.c.poll_id==poll_id))
    c.execute(delete(poll_voters).where(poll_voters.c.poll_id==poll_id))
    c.execute(delete(poll_options).where(poll_options.c.poll_id==poll_id))
    c.execute(delete(poll_deletion_requests).where(poll_deletion_requests.c.poll_id==poll_id))
    c.execute(delete(polls).where(polls.c.id==poll_id))

@app.get('/voting')
@access()
def voting():
    tab = request.args.get('tab','pending')
    if tab not in ('pending','created','results','delete-requests','vote-removals'): tab='pending'
    if tab=='delete-requests' and g.user['role']!='admin': abort(403)
    if tab=='vote-removals' and g.user['role'] not in ('guardian','admin'): abort(403)
    selected_id = request.args.get('poll_id', type=int)
    return render_template('voting.html', **voting_page_data(tab, selected_id))

@app.post('/voting/polls/<int:poll_id>/edit')
@access('guardian','admin')
def edit_unstarted_poll(poll_id):
    title=request.form.get('title','').strip()
    start_value=request.form.get('starts_at','').strip()
    end_value=request.form.get('ends_at','').strip()
    if not title or len(title)>200:
        flash('Nazwa głosowania musi mieć od 1 do 200 znaków.', 'error')
        return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')
    if bool(start_value) != bool(end_value):
        flash('Podaj obie daty albo pozostaw obie puste.', 'error')
        return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')
    start=end=None
    if start_value:
        start=local_datetime(start_value)
        end=local_datetime(end_value)
        if start<=now() or end<=start:
            flash('Data początku musi być w przyszłości, a koniec późniejszy od początku.', 'error')
            return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')
    with engine.begin() as c:
        poll=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
        if not poll: abort(404)
        if poll['archived'] or poll_state(poll) not in ('draft','scheduled'): abort(400, 'Nie można edytować głosowania, które już się rozpoczęło lub zostało usunięte.')
        if start and not c.scalar(select(func.count()).select_from(poll_options).where(poll_options.c.poll_id==poll_id)):
            flash('Dodaj co najmniej jeden pomysł przed ustawieniem dat głosowania.', 'error')
            return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')
        c.execute(update(polls).where(polls.c.id==poll_id).values(title=title,starts_at=start.isoformat(timespec='minutes') if start else None,ends_at=end.isoformat(timespec='minutes') if end else None))
    flash('Zapisano zmiany w głosowaniu.', 'success')
    return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')

@app.post('/voting/polls/<int:poll_id>/options/<int:option_id>/remove')
@access('guardian','admin')
def remove_poll_option(poll_id, option_id):
    with engine.begin() as c:
        poll=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
        option=c.execute(select(poll_options).where(poll_options.c.id==option_id,poll_options.c.poll_id==poll_id).with_for_update()).mappings().first()
        if not poll or not option: abort(404)
        if poll['archived'] or poll_state(poll) not in ('draft','scheduled'): abort(400, 'Pomysł można usunąć tylko przed rozpoczęciem głosowania.')
        if option['source_type'] in ('internal','external') and option['source_id']:
            c.execute(update(vote_requests).where(vote_requests.c.source_type==option['source_type'],vote_requests.c.source_id==option['source_id'],vote_requests.c.poll_id==poll_id).values(status='pending',poll_id=None))
        c.execute(delete(poll_options).where(poll_options.c.id==option_id))
    flash('Usunięto pomysł z głosowania. Zgłoszenie wróciło do oczekujących.', 'success')
    return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')

@app.post('/voting/polls/<int:poll_id>/delete-request')
@access('guardian','admin')
def request_poll_deletion(poll_id):
    removed = g.user['role']=='admin'
    with engine.begin() as c:
        poll=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
        if not poll: abort(404)
        if g.user['role']=='admin':
            if poll_state(poll) in ('draft','scheduled'):
                delete_unstarted_poll(c,poll_id)
                flash('Usunięto nie rozpoczęte głosowanie.', 'success')
            else:
                c.execute(update(polls).where(polls.c.id==poll_id).values(archived=1,results_public=0))
                c.execute(delete(poll_deletion_requests).where(poll_deletion_requests.c.poll_id==poll_id))
                flash('Usunięto głosowanie z portalu. Dane głosujących zostały zachowane.', 'success')
        else:
            if poll_state(poll) not in ('draft','scheduled'): abort(400, 'Można zgłaszać do usunięcia tylko głosowania, które jeszcze się nie rozpoczęły.')
            exists=c.scalar(select(poll_deletion_requests.c.poll_id).where(poll_deletion_requests.c.poll_id==poll_id))
            if exists: flash('Prośba o usunięcie tego głosowania już czeka na administratora.')
            else:
                c.execute(insert(poll_deletion_requests).values(poll_id=poll_id,requester=g.user['id'],created=now().isoformat(timespec='minutes')))
                flash('Wysłano prośbę o usunięcie do administratora.', 'success')
    return redirect('/voting?tab=created' if removed else '/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')

@app.post('/voting/poll-deletion-requests/<int:poll_id>')
@access('admin')
def decide_poll_deletion(poll_id):
    action=request.form.get('action')
    if action not in ('approve','reject'): abort(400)
    with engine.begin() as c:
        pending=c.execute(select(poll_deletion_requests).where(poll_deletion_requests.c.poll_id==poll_id).with_for_update()).mappings().first()
        if not pending: abort(404)
        if action=='approve':
            poll=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
            if poll and poll_state(poll) in ('draft','scheduled'):
                delete_unstarted_poll(c,poll_id)
                flash('Zatwierdzono prośbę i usunięto głosowanie.', 'success')
            else:
                c.execute(delete(poll_deletion_requests).where(poll_deletion_requests.c.poll_id==poll_id))
                flash('Głosowanie już się rozpoczęło, więc prośba nie może być zatwierdzona.', 'error')
        else:
            c.execute(delete(poll_deletion_requests).where(poll_deletion_requests.c.poll_id==poll_id))
            flash('Odrzucono prośbę o usunięcie.', 'success')
    return redirect('/voting?tab=delete-requests')

@app.post('/voting/polls/<int:poll_id>/end-early')
@access('admin')
def end_poll_early(poll_id):
    with engine.begin() as c:
        poll=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
        if not poll: abort(404)
        if poll['archived'] or poll_state(poll)!='open': abort(400, 'Administrator może zakończyć tylko trwające głosowanie.')
        c.execute(update(polls).where(polls.c.id==poll_id).values(ends_at=now().isoformat(timespec='seconds')))
    flash('Zakończono głosowanie przed zaplanowanym terminem.', 'success')
    return redirect('/voting?tab=results&poll_id='+str(poll_id))

@app.post('/voting/polls/<int:poll_id>/publish-results')
@access('guardian','admin')
def publish_poll_results(poll_id):
    publish=request.form.get('publish')
    if publish not in ('1','0'): abort(400)
    with engine.begin() as c:
        poll=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
        if not poll: abort(404)
        if poll['archived'] or poll_state(poll)!='closed': abort(400, 'Wyniki można opublikować dopiero po zakończeniu głosowania.')
        c.execute(update(polls).where(polls.c.id==poll_id).values(results_public=int(publish)))
    flash('Wyniki są teraz widoczne publicznie.' if publish=='1' else 'Wyniki przestały być widoczne publicznie.', 'success')
    return redirect('/voting?tab=results&poll_id='+str(poll_id))

@app.post('/voting/requests/<int:request_id>')
@access('guardian','admin')
def decide_vote_request(request_id):
    action = request.form.get('action')
    if action not in ('approve','reject'): abort(400)
    with engine.begin() as c:
        item = c.execute(select(vote_requests).where(vote_requests.c.id==request_id).with_for_update()).mappings().first()
        if not item or item['status']!='pending': abort(404)
        if action == 'reject':
            c.execute(update(vote_requests).where(vote_requests.c.id==request_id).values(status='rejected'))
            flash('Pomysł odrzucono. Nie zostanie dodany do głosowania.')
        else:
            poll_id = request.form.get('poll_id','').strip()
            title = request.form.get('new_poll_title','').strip()
            if bool(poll_id) == bool(title): abort(400)
            if title:
                if len(title)>200: abort(400)
                poll_id = c.execute(insert(polls).values(title=title,created_by=g.user['id'],created=now().isoformat(timespec='minutes'),starts_at=None,ends_at=None)).inserted_primary_key[0]
            else:
                try: poll_id=int(poll_id)
                except ValueError: abort(400)
                target=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
                if not target or target['archived'] or poll_state(target)!='draft': abort(400)
            c.execute(insert(poll_options).values(poll_id=poll_id,source_type=item['source_type'],source_id=item['source_id'],author_name=item['author_name'],school_class=item['school_class'],body=item['body'],created=now().isoformat(timespec='minutes')))
            c.execute(update(vote_requests).where(vote_requests.c.id==request_id).values(status='approved',poll_id=poll_id))
            flash('Pomysł dodano jako opcję głosowania. Głosowanie można uruchomić w zakładce „Utworzone głosowania”.', 'success')
    return redirect('/voting?tab=' + ('pending' if action=='reject' else 'created'))

@app.post('/voting/polls/<int:poll_id>/schedule')
@access('guardian','admin')
def schedule_poll(poll_id):
    start_value=request.form.get('starts_at','').strip()
    end_value=request.form.get('ends_at','').strip()
    try:
        start=(datetime.strptime(start_value,'%Y-%m-%dT%H:%M').replace(tzinfo=ZoneInfo('Europe/Warsaw'))
               if start_value else now().replace(second=0,microsecond=0))
        end=datetime.strptime(end_value,'%Y-%m-%dT%H:%M').replace(tzinfo=ZoneInfo('Europe/Warsaw'))
    except ValueError:
        flash('Wybierz prawidłową datę i godzinę zakończenia oraz — jeśli głosowanie ma ruszyć później — rozpoczęcia.', 'error')
        return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')
    current_minute=now().replace(second=0,microsecond=0)
    if start < current_minute or end <= start:
        flash('Data rozpoczęcia nie może być wcześniejsza niż bieżąca minuta, a zakończenie musi być późniejsze od rozpoczęcia.', 'error')
        return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')
    with engine.begin() as c:
        poll=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
        if not poll: abort(404)
        if poll['archived'] or poll_state(poll)!='draft': abort(400)
        if not c.scalar(select(func.count()).select_from(poll_options).where(poll_options.c.poll_id==poll_id)):
            flash('Dodaj co najmniej jeden pomysł do tego głosowania przed jego uruchomieniem.')
            return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')
        c.execute(update(polls).where(polls.c.id==poll_id).values(starts_at=start.isoformat(timespec='minutes'),ends_at=end.isoformat(timespec='minutes')))
    flash('Ustawiono harmonogram głosowania.', 'success')
    return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')

def cast_ballot(poll_id, option_id, kind, display_name, school_class='', internal_user=None):
    try:
        with engine.begin() as c:
            poll=c.execute(select(polls).where(polls.c.id==poll_id)).mappings().first()
            if not poll or poll['archived'] or poll_state(poll)!='open':
                return False, 'To głosowanie nie jest teraz otwarte.'
            option=c.scalar(select(poll_options.c.id).where(poll_options.c.id==option_id,poll_options.c.poll_id==poll_id))
            if not option: return False, 'Wybierz jedną z dostępnych propozycji.'
            ballot_key=secrets.token_hex(32)
            values=dict(poll_id=poll_id,kind=kind,internal_user=internal_user,external_key=external_voter_key(display_name) if kind=='external' else None,ballot_key=ballot_key,display_name=display_name[:160],school_class=school_class[:60] or None,created=now().isoformat(timespec='minutes'),anonymized=0)
            # Klucz pozwala usunąć głos razem z danymi po zatwierdzeniu prośby; wyniki nie pokazują tego powiązania.
            c.execute(insert(poll_voters).values(id=secrets.randbits(62)+1,**values))
            c.execute(insert(secret_ballots).values(id=secrets.randbits(62)+1,ballot_key=ballot_key,poll_id=poll_id,option_id=option_id))
        return True, 'Głos został zapisany. Nie da się go przypisać do konkretnej osoby.'
    except IntegrityError:
        return False, 'Już oddałeś/aś głos.'

@app.post('/voting/polls/<int:poll_id>/vote')
@access('student','guardian','admin')
def cast_internal_vote(poll_id):
    try: option_id=int(request.form.get('option_id',''))
    except ValueError: abort(400)
    ok, message = cast_ballot(poll_id,option_id,'internal',g.user['name'],internal_user=g.user['id'])
    flash(message, 'success' if ok else 'error')
    return redirect('/voting?tab=created&poll_id='+str(poll_id)+'#poll-detail')

@app.get('/public-voting')
def public_voting():
    listed=[]
    for poll in sorted(rows(polls, polls.c.archived == 0),key=lambda p:p['id'],reverse=True):
        state=poll_state(poll)
        if state in ('scheduled','open'):
            listed.append(dict(poll, state=state))
    return render_template('public_voting.html', polls=listed)

@app.get('/public-results')
def public_poll_results():
    results=published_results()
    selected_id=request.args.get('poll_id',type=int)
    selected=next((item for item in results if item['poll']['id']==selected_id),None)
    return render_template('public_results.html', results=results, selected=selected)

@app.route('/public-voting/<int:poll_id>', methods=['GET','POST'])
def public_vote(poll_id):
    found=rows(polls,(polls.c.id==poll_id) & (polls.c.archived==0))
    if not found or poll_state(found[0]) not in ('scheduled','open'): abort(404)
    poll=found[0]
    state=poll_state(poll)
    if request.method=='POST':
        name=' '.join(request.form.get('name','').split())
        school_class=request.form.get('school_class','').strip()
        try: option_id=int(request.form.get('option_id',''))
        except ValueError: abort(400)
        if len(name)>160 or len(name.split())<2 or not school_class or len(school_class)>60:
            flash('Wpisz imię i nazwisko oraz swoją klasę.', 'error')
        elif state!='open':
            flash('To głosowanie nie jest teraz otwarte.', 'error')
        else:
            ok,message=cast_ballot(poll_id,option_id,'external',name,school_class)
            flash(message, 'success' if ok else 'error')
        return redirect(url_for('public_vote',poll_id=poll_id))
    return render_template('external_vote.html',poll=poll,state=state,options=rows(poll_options,poll_options.c.poll_id==poll_id))

def anonymize_external_voter(c, voter_id):
    voter=c.execute(select(poll_voters).where(poll_voters.c.id==voter_id,poll_voters.c.kind=='external').with_for_update()).mappings().first()
    if not voter: return
    if voter['ballot_key']:
        c.execute(delete(secret_ballots).where(secret_ballots.c.ballot_key==voter['ballot_key']))
    c.execute(update(poll_voters).where(poll_voters.c.id==voter_id,poll_voters.c.kind=='external').values(ballot_key=None,external_key=None,display_name=None,school_class=None,anonymized=1))

@app.post('/voting/external-voters/<int:voter_id>/remove')
@access('student','guardian','admin')
def request_external_voter_removal(voter_id):
    with engine.begin() as c:
        voter=c.execute(select(poll_voters).where(poll_voters.c.id==voter_id).with_for_update()).mappings().first()
        if not voter or voter['kind']!='external' or voter['anonymized']: abort(404)
        poll=c.execute(select(polls).where(polls.c.id==voter['poll_id']).with_for_update()).mappings().first()
        if not poll: abort(404)
        if g.user['role'] in ('guardian','admin'):
            anonymize_external_voter(c,voter_id)
            c.execute(delete(poll_voter_removals).where(poll_voter_removals.c.voter_id==voter_id))
            flash('Usunięto dane głosującego zewnętrznego i jego głos z wyników.', 'success')
        else:
            exists=c.scalar(select(poll_voter_removals.c.voter_id).where(poll_voter_removals.c.voter_id==voter_id))
            if not exists: c.execute(insert(poll_voter_removals).values(voter_id=voter_id,requester=g.user['id'],created=now().isoformat(timespec='minutes')))
            flash('Prośba o usunięcie danych czeka na zatwierdzenie opiekuna.')
    return redirect('/voting?tab=results&poll_id=' + str(voter['poll_id']))

@app.post('/voting/external-voters/<int:voter_id>/decision')
@access('guardian','admin')
def decide_external_voter_removal(voter_id):
    decision=request.form.get('decision')
    if decision not in ('approve','reject'): abort(400)
    with engine.begin() as c:
        voter=c.execute(select(poll_voters).where(poll_voters.c.id==voter_id,poll_voters.c.kind=='external').with_for_update()).mappings().first()
        pending=c.scalar(select(poll_voter_removals.c.voter_id).where(poll_voter_removals.c.voter_id==voter_id))
        if not voter or voter['anonymized'] or not pending: abort(404)
        poll=c.execute(select(polls).where(polls.c.id==voter['poll_id']).with_for_update()).mappings().first()
        if not poll: abort(404)
        c.execute(delete(poll_voter_removals).where(poll_voter_removals.c.voter_id==voter_id))
        if decision=='approve': anonymize_external_voter(c,voter_id)
    flash('Usunięto dane głosującego zewnętrznego i jego głos z wyników.' if decision=='approve' else 'Prośbę odrzucono; dane pozostają widoczne.', 'success' if decision=='approve' else 'error')
    return redirect('/voting?tab=results&poll_id=' + str(voter['poll_id']))

def anonymize_internal_voter(c, voter_id):
    voter=c.execute(select(poll_voters).where(poll_voters.c.id==voter_id,poll_voters.c.kind=='internal').with_for_update()).mappings().first()
    if not voter: return
    if voter['ballot_key']:
        c.execute(delete(secret_ballots).where(secret_ballots.c.ballot_key==voter['ballot_key']))
    c.execute(update(poll_voters).where(poll_voters.c.id==voter_id,poll_voters.c.kind=='internal').values(ballot_key=None,internal_user=None,display_name=None,school_class=None,anonymized=1))

@app.post('/voting/internal-voters/<int:voter_id>/remove')
@access('student','guardian','admin')
def request_internal_voter_removal(voter_id):
    with engine.begin() as c:
        voter=c.execute(select(poll_voters).where(poll_voters.c.id==voter_id,poll_voters.c.kind=='internal').with_for_update()).mappings().first()
        if not voter or voter['anonymized']: abort(404)
        if g.user['role']=='student' and voter['internal_user']!=g.user['id']: abort(403)
        poll=c.execute(select(polls).where(polls.c.id==voter['poll_id']).with_for_update()).mappings().first()
        if not poll or poll_state(poll)!='closed': abort(400,'Dane i głosy uczestników można usuwać po zakończeniu głosowania.')
        if g.user['role']=='admin':
            anonymize_internal_voter(c,voter_id)
            c.execute(delete(poll_internal_voter_removals).where(poll_internal_voter_removals.c.voter_id==voter_id))
            flash('Usunięto głos i dane uczestnika.','success')
        else:
            exists=c.scalar(select(poll_internal_voter_removals.c.voter_id).where(poll_internal_voter_removals.c.voter_id==voter_id))
            if exists: flash('Prośba o usunięcie już czeka na administratora.')
            else:
                c.execute(insert(poll_internal_voter_removals).values(voter_id=voter_id,requester=g.user['id'],created=now().isoformat(timespec='minutes')))
                flash('Prośba o usunięcie głosu i danych została wysłana do administratora.','success')
    return redirect('/voting?tab=results&poll_id='+str(voter['poll_id']))

@app.post('/voting/internal-voters/<int:voter_id>/decision')
@access('admin')
def decide_internal_voter_removal(voter_id):
    decision=request.form.get('decision')
    if decision not in ('approve','reject'): abort(400)
    with engine.begin() as c:
        pending=c.execute(select(poll_internal_voter_removals).where(poll_internal_voter_removals.c.voter_id==voter_id).with_for_update()).mappings().first()
        voter=c.execute(select(poll_voters).where(poll_voters.c.id==voter_id,poll_voters.c.kind=='internal').with_for_update()).mappings().first()
        if not pending or not voter: abort(404)
        poll=c.execute(select(polls).where(polls.c.id==voter['poll_id']).with_for_update()).mappings().first()
        if not poll or poll_state(poll)!='closed': abort(400,'Usuwanie danych jest dostępne po zakończeniu głosowania.')
        if decision=='approve': anonymize_internal_voter(c,voter_id)
        c.execute(delete(poll_internal_voter_removals).where(poll_internal_voter_removals.c.voter_id==voter_id))
    flash('Usunięto głos i dane uczestnika.' if decision=='approve' else 'Odrzucono prośbę; dane i głos pozostają.','success' if decision=='approve' else 'error')
    return redirect('/voting?tab=delete-requests')

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

def read_chat_uploads():
    uploads=[item for item in request.files.getlist('attachments') if item and item.filename]
    voice=request.files.get('voice_message')
    if voice and voice.filename: uploads.append(voice)
    if len(uploads)>10: abort(400,'W jednej wiadomości można wysłać maksymalnie 10 plików.')
    result=[]
    total=0
    for upload in uploads:
        data=upload.read(25*1024*1024+1)
        total+=len(data)
        if total>25*1024*1024: abort(400,'Załączniki w jednej wiadomości mogą mieć łącznie maksymalnie 25 MB.')
        if not data: continue
        name=upload.filename.replace('\\','/').split('/')[-1][:255] or 'zalacznik'
        mime=(upload.mimetype or mimetypes.guess_type(name)[0] or 'application/octet-stream').lower()
        result.append(dict(name=name,mime_type=mime,data=data))
    return result

@app.route('/chat',methods=['GET','POST'])
@access()
def chat():
    if request.method=='POST':
        kind=request.form.get('kind','text')
        if kind not in ('text','media','poll','event','contact'): abort(400)
        body=request.form.get('body','').strip()
        if len(body)>5000: abort(400,'Wiadomość może mieć maksymalnie 5000 znaków.')
        uploads=read_chat_uploads()
        poll_data=None
        event_data=None
        contact_data=None
        if kind=='poll':
            try: poll_data=json.loads(request.form.get('poll_payload','{}'))
            except (TypeError,ValueError): abort(400,'Ankieta ma nieprawidłowy format.')
            questions=poll_data.get('questions') if isinstance(poll_data,dict) else None
            if not isinstance(questions,list) or not 1<=len(questions)<=10: abort(400,'Ankieta musi mieć od 1 do 10 pytań.')
            cleaned=[]
            for question in questions:
                if not isinstance(question,dict): abort(400,'Sprawdź treść pytań w ankiecie.')
                question_body=' '.join(str(question.get('body','')).split())
                options=question.get('options')
                if not question_body or len(question_body)>500 or not isinstance(options,list) or not 2<=len(options)<=8: abort(400,'Każde pytanie musi mieć treść oraz co najmniej dwie odpowiedzi.')
                option_values=[' '.join(str(option).split()) for option in options]
                if any(not option or len(option)>200 for option in option_values) or len(set(option.lower() for option in option_values))!=len(option_values): abort(400,'Uzupełnij różne odpowiedzi do każdego pytania.')
                cleaned.append(dict(body=question_body,options=option_values))
            poll_data=dict(questions=cleaned,allow_multiple=int(bool(poll_data.get('allow_multiple'))))
            if uploads: abort(400,'Do ankiety nie można dołączyć plików.')
        elif kind=='event':
            event_title=' '.join(request.form.get('event_title','').split())
            event_date=request.form.get('event_date','').strip()
            event_time=request.form.get('event_time','').strip()
            event_place=' '.join(request.form.get('event_place','').split())
            if not event_title or len(event_title)>160 or not event_date or len(event_place)>160: abort(400,'Uzupełnij nazwę, datę i miejsce wydarzenia.')
            try: datetime.strptime(event_date,'%Y-%m-%d')
            except ValueError: abort(400,'Podaj prawidłową datę wydarzenia.')
            if event_time:
                try: datetime.strptime(event_time,'%H:%M')
                except ValueError: abort(400,'Podaj prawidłową godzinę wydarzenia.')
            event_data=dict(title=event_title,date=event_date,time=event_time,place=event_place,caption=body)
            if uploads: abort(400,'Do wydarzenia nie można dołączyć plików.')
        elif kind=='contact':
            try: contact_id=int(request.form.get('contact_user_id',''))
            except ValueError: abort(400,'Wybierz osobę do udostępnienia.')
            contact=rows(users,users.c.id==contact_id)
            if not contact: abort(400,'Wybrane konto już nie istnieje.')
            contact_data=dict(user_id=contact_id,name=contact[0]['name'],role=ROLES.get(contact[0]['role'],'Użytkownik'),caption=body)
            if uploads: abort(400)
        elif kind=='text' and uploads:
            kind='media'
        if kind in ('text','media') and not body and not uploads: abort(400,'Wpisz wiadomość albo dodaj załącznik.')
        if kind=='event': body=json.dumps(event_data,ensure_ascii=False)
        elif kind=='contact': body=json.dumps(contact_data,ensure_ascii=False)
        with engine.begin() as c:
            message_id=c.execute(insert(chat_messages).values(sender=g.user['id'],kind=kind,body=body,created=now().isoformat(timespec='minutes'),edited=0)).inserted_primary_key[0]
            for file in uploads:
                c.execute(insert(chat_attachments).values(message_id=message_id,**file))
            if poll_data:
                c.execute(insert(chat_polls).values(message_id=message_id,allow_multiple=poll_data['allow_multiple']))
                for position,question in enumerate(poll_data['questions']):
                    question_id=c.execute(insert(chat_poll_questions).values(message_id=message_id,position=position,body=question['body'])).inserted_primary_key[0]
                    c.execute(insert(chat_poll_options),[dict(question_id=question_id,position=index,body=option) for index,option in enumerate(question['options'])])
        return redirect('/chat#message-'+str(message_id))

    with engine.connect() as c:
        message_rows=[dict(item) for item in c.execute(select(chat_messages).order_by(chat_messages.c.id.desc()).limit(120)).mappings()]
        message_rows.reverse()
        message_ids=[item['id'] for item in message_rows]
        attachment_rows=[dict(item) for item in c.execute(select(chat_attachments.c.id,chat_attachments.c.message_id,chat_attachments.c.name,chat_attachments.c.mime_type).where(chat_attachments.c.message_id.in_(message_ids))).mappings()] if message_ids else []
        poll_message_ids=[item['id'] for item in message_rows if item['kind']=='poll']
        poll_settings=[dict(item) for item in c.execute(select(chat_polls).where(chat_polls.c.message_id.in_(poll_message_ids))).mappings()] if poll_message_ids else []
        poll_questions=[dict(item) for item in c.execute(select(chat_poll_questions).where(chat_poll_questions.c.message_id.in_(poll_message_ids)).order_by(chat_poll_questions.c.position)).mappings()] if poll_message_ids else []
        question_ids=[item['id'] for item in poll_questions]
        poll_options_rows=[dict(item) for item in c.execute(select(chat_poll_options).where(chat_poll_options.c.question_id.in_(question_ids)).order_by(chat_poll_options.c.position)).mappings()] if question_ids else []
        poll_vote_rows=[dict(item) for item in c.execute(select(chat_poll_votes).where(chat_poll_votes.c.question_id.in_(question_ids))).mappings()] if question_ids else []
    attachments_by_message={}
    for item in attachment_rows: attachments_by_message.setdefault(item['message_id'],[]).append(item)
    settings_by_message={item['message_id']:item for item in poll_settings}
    questions_by_message={}
    for item in poll_questions: questions_by_message.setdefault(item['message_id'],[]).append(item)
    options_by_question={}
    for item in poll_options_rows: options_by_question.setdefault(item['question_id'],[]).append(item)
    votes_by_question={}
    for item in poll_vote_rows: votes_by_question.setdefault(item['question_id'],[]).append(item)
    users_by_id={item['id']:dict(item) for item in rows(users)}
    for message in message_rows:
        sender=users_by_id.get(message['sender'])
        message['sender_name']=sender['name'] if sender else 'Usunięte konto'
        message['sender_role']=ROLES.get(sender['role'],'Użytkownik') if sender else 'Użytkownik'
        message['own']=message['sender']==g.user['id']
        message['attachments']=attachments_by_message.get(message['id'],[])
        message['event_data']=None
        message['contact_data']=None
        message['edit_body']=message['body']
        message['poll_data']=None
        if message['kind']=='event':
            try: message['event_data']=json.loads(message['body'])
            except (TypeError,ValueError): message['event_data']={}
            message['edit_body']=message['event_data'].get('caption','')
        elif message['kind']=='contact':
            try: message['contact_data']=json.loads(message['body'])
            except (TypeError,ValueError): message['contact_data']={}
            message['edit_body']=message['contact_data'].get('caption','')
        elif message['kind']=='poll':
            settings=settings_by_message.get(message['id'])
            questions=questions_by_message.get(message['id'],[])
            poll_questions=[]
            for question in questions:
                options=options_by_question.get(question['id'],[])
                question_votes=votes_by_question.get(question['id'],[])
                selected_options={vote['option_id'] for vote in question_votes if vote['voter_id']==g.user['id']}
                poll_questions.append(dict(question,options=[dict(option,votes=sum(vote['option_id']==option['id'] for vote in question_votes),selected=option['id'] in selected_options) for option in options],total=len(question_votes)))
            message['poll_data']=dict(allow_multiple=bool(settings and settings['allow_multiple']),questions=poll_questions)
    contacts=sorted((dict(id=item['id'],name=item['name'],role=item['role']) for item in users_by_id.values()),key=lambda item:item['name'].lower())
    return render_template('chat.html',messages=message_rows,contacts=contacts)

@app.post('/chat/<int:message_id>/edit')
@access()
def edit_chat_message(message_id):
    message=rows(chat_messages,chat_messages.c.id==message_id)
    if not message: abort(404)
    if message[0]['sender']!=g.user['id']: abort(403)
    body=request.form.get('body','').strip()
    if len(body)>5000: abort(400)
    if message[0]['kind']=='text' and not body: abort(400,'Wiadomość tekstowa nie może być pusta.')
    if message[0]['kind']=='event':
        try: payload=json.loads(message[0]['body'])
        except (TypeError,ValueError): abort(400)
        title=' '.join(request.form.get('event_title','').split())
        event_date=request.form.get('event_date','').strip()
        event_time=request.form.get('event_time','').strip()
        place=' '.join(request.form.get('event_place','').split())
        if not title or len(title)>160 or not event_date or len(place)>160: abort(400,'Uzupełnij nazwę, datę i miejsce wydarzenia.')
        try: datetime.strptime(event_date,'%Y-%m-%d')
        except ValueError: abort(400,'Podaj prawidłową datę wydarzenia.')
        if event_time:
            try: datetime.strptime(event_time,'%H:%M')
            except ValueError: abort(400,'Podaj prawidłową godzinę wydarzenia.')
        payload.update(title=title,date=event_date,time=event_time,place=place,caption=body)
        body=json.dumps(payload,ensure_ascii=False)
    elif message[0]['kind']=='contact':
        try: payload=json.loads(message[0]['body'])
        except (TypeError,ValueError): abort(400)
        try: contact_id=int(request.form.get('contact_user_id',''))
        except ValueError: abort(400,'Wybierz osobę do udostępnienia.')
        contact=rows(users,users.c.id==contact_id)
        if not contact: abort(400,'Wybrane konto już nie istnieje.')
        payload.update(user_id=contact_id,name=contact[0]['name'],role=ROLES.get(contact[0]['role'],'Użytkownik'),caption=body)
        body=json.dumps(payload,ensure_ascii=False)
    with engine.begin() as c:
        c.execute(update(chat_messages).where(chat_messages.c.id==message_id,chat_messages.c.sender==g.user['id']).values(body=body,edited=1))
    flash('Zmieniono własną wiadomość.','success')
    return redirect('/chat#message-'+str(message_id))

@app.post('/chat/<int:message_id>/delete')
@access()
def delete_chat_message(message_id):
    with engine.begin() as c:
        message=c.execute(select(chat_messages).where(chat_messages.c.id==message_id).with_for_update()).mappings().first()
        if not message: abort(404)
        if message['sender']!=g.user['id']: abort(403)
        question_ids=[item['id'] for item in c.execute(select(chat_poll_questions.c.id).where(chat_poll_questions.c.message_id==message_id)).mappings()]
        if question_ids:
            option_ids=[item['id'] for item in c.execute(select(chat_poll_options.c.id).where(chat_poll_options.c.question_id.in_(question_ids))).mappings()]
            c.execute(delete(chat_poll_votes).where(chat_poll_votes.c.question_id.in_(question_ids)))
            if option_ids: c.execute(delete(chat_poll_options).where(chat_poll_options.c.id.in_(option_ids)))
            c.execute(delete(chat_poll_questions).where(chat_poll_questions.c.id.in_(question_ids)))
        c.execute(delete(chat_polls).where(chat_polls.c.message_id==message_id))
        c.execute(delete(chat_attachments).where(chat_attachments.c.message_id==message_id))
        c.execute(delete(chat_messages).where(chat_messages.c.id==message_id,chat_messages.c.sender==g.user['id']))
    flash('Usunięto własną wiadomość.','success')
    return redirect('/chat')

@app.post('/chat/polls/<int:message_id>/questions/<int:question_id>/vote')
@access()
def vote_in_chat_poll(message_id,question_id):
    try: option_ids=list(dict.fromkeys(int(value) for value in request.form.getlist('option_id')))
    except ValueError: abort(400)
    with engine.begin() as c:
        poll=c.execute(select(chat_polls).where(chat_polls.c.message_id==message_id).with_for_update()).mappings().first()
        question=c.execute(select(chat_poll_questions).where(chat_poll_questions.c.id==question_id,chat_poll_questions.c.message_id==message_id)).mappings().first()
        if not poll or not question or not option_ids: abort(400,'Wybierz co najmniej jedną odpowiedź.')
        if not poll['allow_multiple'] and len(option_ids)>1: abort(400,'Wybierz jedną odpowiedź.')
        valid={item['id'] for item in c.execute(select(chat_poll_options.c.id).where(chat_poll_options.c.question_id==question_id)).mappings()}
        if any(option_id not in valid for option_id in option_ids): abort(400)
        c.execute(delete(chat_poll_votes).where(chat_poll_votes.c.question_id==question_id,chat_poll_votes.c.voter_id==g.user['id']))
        c.execute(insert(chat_poll_votes),[dict(question_id=question_id,option_id=option_id,voter_id=g.user['id']) for option_id in option_ids])
    return redirect('/chat#message-'+str(message_id))

@app.get('/chat/files/<int:file_id>')
@access()
def chat_file(file_id):
    found=rows(chat_attachments,chat_attachments.c.id==file_id)
    if not found: abort(404)
    file=found[0]
    message=rows(chat_messages,chat_messages.c.id==file['message_id'])
    if not message: abort(404)
    inline_types={'image/jpeg','image/png','image/gif','image/webp','audio/mpeg','audio/ogg','audio/wav','audio/webm','audio/mp4','video/mp4','video/webm','video/ogg'}
    inline=file['mime_type'] in inline_types
    response=send_file(io.BytesIO(file['data']),download_name=file['name'],mimetype=file['mime_type'] if inline else 'application/octet-stream',as_attachment=not inline,conditional=False)
    if inline:
        response.headers['Content-Security-Policy']="default-src 'none'; img-src 'self'; media-src 'self'; sandbox"
        response.headers['Content-Disposition']='inline'
    return response

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
