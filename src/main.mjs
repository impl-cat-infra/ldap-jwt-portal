import Koa from 'koa';
import KoaBP from 'koa-bodyparser';
import ldap from 'ldapjs';
import jwt from 'jsonwebtoken';

import * as CFG from './config.mjs';
import fs from 'fs/promises';

async function auth(user, pass) {
  const conn = ldap.createClient({
    url: CFG.LDAP_REMOTE,
  });
  await new Promise((resolve, reject) => conn.bind(`uid=${user},ou=People,dc=impl,dc=cat`, pass, (err) => {
    if(err) reject(err);
    else resolve();
  }));

  console.log(`Basic auth passed for ${user}`);

  const uid = await new Promise((resolve, reject) => conn.search(`uid=${user},ou=People,dc=impl,dc=cat`, {
    attributes: ['uidNumber'],
  }, (err, res) => {
    if(err) reject(err);
    res.on('searchEntry', ent => {
      resolve(ent.object.uidNumber);
    });
    res.on('error', (err) => {
      console.error('error: ' + err.message);
      reject(err);
    });
  }));

  return parseInt(uid, 10);
}

const app = new Koa();

app.use(KoaBP());

const indexParams = {
  TITLE: CFG.TITLE,
  SUBTITLE: CFG.SUBTITLE,
}

async function getIndex() {
  const buf = await fs.readFile('index.html');
  let tmpl = buf.toString('utf-8');
  for(const k in indexParams)
    tmpl = tmpl.replace(`{{${k}}}`, indexParams[k]);
  return tmpl;
}

app.use(async ctx => {
  if(ctx.method === 'GET') {
    if(ctx.request.path === '/auth') {
      const token = ctx.cookies.get(CFG.JWT_COOKIE_NAME);
      if((token ?? '') == '') return ctx.status = 403;
      let verified;
      try {
        verified = jwt.verify(token, CFG.JWT_KEY);
      } catch(e) {
        return ctx.status = 403;
      }

      const upstream = '127.0.0.1:' + verified.port;
      ctx.set('X_UpstreamHost', upstream);

      return ctx.status = 200;
    } else {
      ctx.body = await getIndex();
      return ctx.status = 200;
    }
  } else if(ctx.method === 'POST') {
    if((ctx.request.body?.user ?? '') === '') return ctx.status = 400;
    if((ctx.request.body?.pass ?? '') === '') return ctx.status = 400;

    try {
      const uid = await auth(ctx.request.body.user, ctx.request.body.pass);
      const port = uid + CFG.PORT_OFFSET;
      // Oh no CPU burning
      const token = jwt.sign({
        user: ctx.request.body.user,
        port,
      }, CFG.JWT_KEY);

      ctx.cookies.set(CFG.JWT_COOKIE_NAME, token);
      ctx.body = { ok: true };
      return ctx.status = 200;
    } catch(e) {
      console.error(e);
      return ctx.status = 403;
    }
  } else {
    ctx.status = 404;
  }
});

app.listen(CFG.PORT);
