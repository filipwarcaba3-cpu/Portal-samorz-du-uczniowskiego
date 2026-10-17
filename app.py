import os, secrets, io, time, hmac, hashlib, unicodedata
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlsplit
from flask import Flask, request, session, redirect, url_for, render_template, flash, abort, g, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, BigInteger, String, Text, LargeBinary, UniqueConstraint, select, insert, update, delete, func
from sqlalchemy.exc import IntegrityError

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
external_ideas = Table('external_ideas', meta, Column('id', Integer, primary_key=True), Column('name', String(160)), Column('school_class', String(60)), Column('body', Text), Column('created', String(30)))
idea_removals = Table('external_idea_removals', meta, Column('idea', Integer, primary_key=True), Column('requester', Integer), Column('created', String(30)))
vote_requests = Table('vote_requests', meta, Column('id', Integer, primary_key=True), Column('source_type', String(20), nullable=False), Column('source_id', Integer, nullable=False), Column('requester', Integer), Column('author_name', String(160)), Column('school_class', String(60)), Column('body', Text), Column('status', String(20), nullable=False, default='pending'), Column('poll_id', Integer), Column('created', String(30)), UniqueConstraint('source_type','source_id',name='uq_vote_request_source'))
polls = Table('polls', meta, Column('id', Integer, primary_key=True), Column('title', String(200), nullable=False), Column('created_by', Integer), Column('created', String(30)), Column('starts_at', String(40)), Column('ends_at', String(40)))
poll_options = Table('poll_options', meta, Column('id', Integer, primary_key=True), Column('poll_id', Integer, nullable=False), Column('source_type', String(20)), Column('source_id', Integer), Column('author_name', String(160)), Column('school_class', String(60)), Column('body', Text, nullable=False), Column('created', String(30)))
poll_voters = Table('poll_voters', meta, Column('id', BigInteger, primary_key=True), Column('poll_id', Integer, nullable=False), Column('kind', String(20), nullable=False), Column('internal_user', Integer), Column('external_key', String(64)), Column('ballot_key', String(64), unique=True), Column('display_name', String(160)), Column('school_class', String(60)), Column('created', String(30)), Column('anonymized', Integer, default=0), UniqueConstraint('poll_id','internal_user',name='uq_poll_internal_voter'), UniqueConstraint('poll_id','external_key',name='uq_poll_external_voter'))
secret_ballots = Table('secret_ballots', meta, Column('id', BigInteger, primary_key=True), Column('ballot_key', String(64), unique=True, nullable=False), Column('poll_id', Integer, nullable=False), Column('option_id', Integer, nullable=False))
poll_voter_removals = Table('poll_voter_removals', meta, Column('voter_id', BigInteger, primary_key=True), Column('requester', Integer), Column('created', String(30)))
portal_settings = Table('portal_settings', meta, Column('key', String(100), primary_key=True), Column('value', Text, nullable=False))
meta.create_all(engine)
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

@app.post('/external-ideas')
def submit_external_idea():
    values = {key: request.form.get(key,'').strip() for key in ('name','school_class','body')}
    if not all(values.values()):
        return render_template('login.html', external_values=values, external_error='Uzupełnij wszystkie trzy pola.', show_external_form=True), 400
    if len(values['name'])>160 or len(values['school_class'])>60 or len(values['body'])>10000:
        return render_template('login.html', external_values=values, external_error='Imię i nazwisko: do 160 znaków; klasa: do 60; pomysł: do 10 000.', show_external_form=True), 400
    with engine.begin() as c:
        c.execute(insert(external_ideas).values(**values, created=now().strftime('%Y-%m-%dT%H:%M')))
    flash('Twój pomysł został wysłany do skrzynki pomysłów samorządu. Dziękujemy!', 'success')
    return redirect('/login')

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
    return render_template('ideas.html', entries=rows(ideas)[::-1], names={u['id']:u['name'] for u in rows(users)}, editing=None, external_entries=rows(external_ideas)[::-1], pending_removals={r['idea']:r for r in rows(idea_removals)}, vote_request_status={(r['source_type'],r['source_id']):r for r in rows(vote_requests)})

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
@access('student')
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
    values = dict(requester=g.user['id'], author_name=name[:160], school_class=school_class[:60], body=body[:10000], status='pending', poll_id=None, created=now().isoformat(timespec='minutes'))
    with engine.begin() as c:
        prior = c.execute(select(vote_requests).where(vote_requests.c.source_type==source_type, vote_requests.c.source_id==item_id).with_for_update()).mappings().first()
        if prior and prior['status'] in ('pending','approved'):
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
    poll_rows = sorted(rows(polls), key=lambda p:p['id'], reverse=True)
    enriched = []
    for poll in poll_rows:
        item = dict(poll)
        item['state'] = poll_state(poll)
        item['options'] = rows(poll_options, poll_options.c.poll_id==poll['id'])
        item['already_voted'] = bool(rows(poll_voters, (poll_voters.c.poll_id==poll['id']) & (poll_voters.c.internal_user==g.user['id'])))
        enriched.append(item)
    pending = [dict(r, requester_name=people.get(r['requester'],'Usunięte konto')) for r in rows(vote_requests, vote_requests.c.status=='pending')]
    pending.sort(key=lambda r:r['created'] or '', reverse=True)
    active = [p for p in enriched if p['state'] in ('scheduled','open')]
    finished = [p for p in enriched if p['state']=='closed']
    selected = next((p for p in enriched if p['id']==selected_id), None)
    detail = None
    if selected and selected['state']=='closed':
        voter_rows = rows(poll_voters, poll_voters.c.poll_id==selected['id'])
        ballots = rows(secret_ballots, secret_ballots.c.poll_id==selected['id'])
        options = []
        for option in selected['options']:
            options.append(dict(option, votes=sum(b['option_id']==option['id'] for b in ballots)))
        removals = {r['voter_id']:r for r in rows(poll_voter_removals)}
        voters_internal = [v for v in voter_rows if v['kind']=='internal']
        voters_external = [dict(v, removal=removals.get(v['id'])) for v in voter_rows if v['kind']=='external' and not v['anonymized']]
        voters_internal.sort(key=lambda v:v['display_name'] or '')
        voters_external.sort(key=lambda v:v['display_name'] or '')
        detail = dict(poll=selected, options=options, internal_voters=voters_internal, external_voters=voters_external)
    return dict(tab=tab, pending_requests=pending, all_polls=enriched, draft_polls=[p for p in enriched if p['state']=='draft'], active_polls=active, finished_polls=finished, selected_poll=selected, detail=detail, people=people)

@app.get('/voting')
@access()
def voting():
    tab = request.args.get('tab','pending')
    if tab not in ('pending','created','results'): tab='pending'
    selected_id = request.args.get('poll_id', type=int)
    return render_template('voting.html', **voting_page_data(tab, selected_id))

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
                if not target or poll_state(target)!='draft': abort(400)
            c.execute(insert(poll_options).values(poll_id=poll_id,source_type=item['source_type'],source_id=item['source_id'],author_name=item['author_name'],school_class=item['school_class'],body=item['body'],created=now().isoformat(timespec='minutes')))
            c.execute(update(vote_requests).where(vote_requests.c.id==request_id).values(status='approved',poll_id=poll_id))
            flash('Pomysł dodano jako opcję głosowania. Głosowanie można uruchomić w zakładce „Utworzone głosowania”.', 'success')
    return redirect('/voting?tab=' + ('pending' if action=='reject' else 'created'))

@app.post('/voting/polls/<int:poll_id>/schedule')
@access('guardian','admin')
def schedule_poll(poll_id):
    start = local_datetime(request.form.get('starts_at',''))
    end = local_datetime(request.form.get('ends_at',''))
    if end <= start or end <= now():
        flash('Data zakończenia musi być późniejsza od rozpoczęcia i od obecnej chwili.')
        return redirect('/voting?tab=created')
    with engine.begin() as c:
        poll=c.execute(select(polls).where(polls.c.id==poll_id).with_for_update()).mappings().first()
        if not poll: abort(404)
        if poll_state(poll)!='draft': abort(400)
        if not c.scalar(select(func.count()).select_from(poll_options).where(poll_options.c.poll_id==poll_id)):
            flash('Dodaj co najmniej jeden pomysł do tego głosowania przed jego uruchomieniem.')
            return redirect('/voting?tab=created')
        c.execute(update(polls).where(polls.c.id==poll_id).values(starts_at=start.isoformat(timespec='minutes'),ends_at=end.isoformat(timespec='minutes')))
    flash('Ustawiono harmonogram głosowania.', 'success')
    return redirect('/voting?tab=created')

def cast_ballot(poll_id, option_id, kind, display_name, school_class='', internal_user=None):
    try:
        with engine.begin() as c:
            poll=c.execute(select(polls).where(polls.c.id==poll_id)).mappings().first()
            if not poll or poll_state(poll)!='open':
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
@access()
def cast_internal_vote(poll_id):
    try: option_id=int(request.form.get('option_id',''))
    except ValueError: abort(400)
    ok, message = cast_ballot(poll_id,option_id,'internal',g.user['name'],internal_user=g.user['id'])
    flash(message, 'success' if ok else 'error')
    return redirect('/voting?tab=created')

@app.get('/public-voting')
def public_voting():
    listed=[]
    for poll in sorted(rows(polls),key=lambda p:p['id'],reverse=True):
        state=poll_state(poll)
        if state in ('scheduled','open'):
            listed.append(dict(poll, state=state))
    return render_template('public_voting.html', polls=listed)

@app.route('/public-voting/<int:poll_id>', methods=['GET','POST'])
def public_vote(poll_id):
    found=rows(polls,polls.c.id==poll_id)
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
    c.execute(update(poll_voters).where(poll_voters.c.id==voter_id,poll_voters.c.kind=='external').values(ballot_key=None,display_name=None,school_class=None,anonymized=1))

@app.post('/voting/external-voters/<int:voter_id>/remove')
@access('student','guardian','admin')
def request_external_voter_removal(voter_id):
    with engine.begin() as c:
        voter=c.execute(select(poll_voters).where(poll_voters.c.id==voter_id).with_for_update()).mappings().first()
        if not voter or voter['kind']!='external': abort(404)
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
        if not voter or not pending: abort(404)
        c.execute(delete(poll_voter_removals).where(poll_voter_removals.c.voter_id==voter_id))
        if decision=='approve': anonymize_external_voter(c,voter_id)
    flash('Usunięto dane głosującego zewnętrznego i jego głos z wyników.' if decision=='approve' else 'Prośbę odrzucono; dane pozostają widoczne.', 'success' if decision=='approve' else 'error')
    return redirect('/voting?tab=results&poll_id=' + str(voter['poll_id']))

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
