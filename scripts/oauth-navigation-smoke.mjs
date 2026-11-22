import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
if (!process.env.PLAYWRIGHT_MODULE) throw new Error("请通过 PLAYWRIGHT_MODULE 指定本机统一 Playwright 模块");
const { chromium } = await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE).href);
const repo = fileURLToPath(new URL("../", import.meta.url));
fs.mkdirSync(path.join(repo, "bin"), { recursive: true });

const temp=fs.mkdtempSync(path.join(repo,"bin/navigation-oauth-"));
const root=path.join(temp,"project");fs.mkdirSync(root);
const key=path.join(temp,"key.pem"),cert=path.join(temp,"cert.pem");
execFileSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,"-days","1","-subj","/CN=localhost"],{stdio:"ignore"});
const reserve=net.createServer();await new Promise(r=>reserve.listen(0,"127.0.0.1",r));
const backendPort=reserve.address().port;await new Promise(r=>reserve.close(r));
let callback,submittedOrigin,disableAuto=false,googleVisits=0,geminiVisits=0;
const proxy=https.createServer({key:fs.readFileSync(key,"utf8"),cert:fs.readFileSync(cert,"utf8")},(req,res)=>{
  const host=req.headers.host.split(":")[0];
  if(host==="oauth-redirect.googleusercontent.com") {
    googleVisits++;callback=new URL(req.url,"https://oauth-redirect.googleusercontent.com");
    res.writeHead(302,{Location:"https://gemini.google.com/oauth-test-complete"});res.end();return;
  }
  if(host==="gemini.google.com") {geminiVisits++;res.setHeader("Content-Type","text/plain; charset=utf-8");res.end("模拟 Gemini 已完成连接");return;}
  if(req.method==="POST"&&req.url==="/oauth/authorize")submittedOrigin=req.headers.origin;
  const upstream=http.request({hostname:"127.0.0.1",port:backendPort,path:req.url,method:req.method,headers:req.headers},received=>{
    if(disableAuto&&req.method==="POST"&&received.statusCode===200) {
      const chunks=[];received.on("data",chunk=>chunks.push(chunk));received.on("end",()=>{
        const body=Buffer.concat(chunks).toString("utf8").replace(/<meta http-equiv="refresh"[^>]*>/," ");
        const headers={...received.headers,"content-length":Buffer.byteLength(body)};delete headers["transfer-encoding"];
        res.writeHead(received.statusCode,headers);res.end(body);
      });
    } else {res.writeHead(received.statusCode,received.headers);received.pipe(res);}
  });
  upstream.on("error",()=>{res.statusCode=502;res.end();});req.pipe(upstream);
});
await new Promise(r=>proxy.listen(0,"127.0.0.1",r));
const tlsPort=proxy.address().port,issuer=`https://127.0.0.1:${tlsPort}`,backend=`http://127.0.0.1:${backendPort}`;
const password=crypto.randomBytes(24).toString("hex");
const child=spawn(path.resolve(process.env.OAUTH_SMOKE_BINARY||path.join(repo,"bin/local-files-mcp")),["-listen",`127.0.0.1:${backendPort}`,"-root",root,"-oauth-issuer",issuer,"-oauth-state",path.join(temp,"private","oauth.json")],{stdio:"ignore",env:{...process.env,LOCAL_FILES_MCP_TOKEN:"",LOCAL_FILES_MCP_PASSWORD:password}});
let browser;
try {
  let ready=false;
  for(let i=0;i<100;i++){if(child.exitCode!==null)throw new Error("测试服务退出");try{if((await fetch(backend+"/healthz")).ok){ready=true;break;}}catch{}await delay(100);}
  if(!ready)throw new Error("测试服务启动超时");
  const redirect="https://oauth-redirect.googleusercontent.com/r/browser-multihop";
  const registration=await fetch(backend+"/oauth/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({client_name:"Browser multi-hop check",redirect_uris:[redirect],token_endpoint_auth_method:"client_secret_post"})});
  if(registration.status!==201)throw new Error("测试注册失败");const client=await registration.json();
  const rules=`MAP oauth-redirect.googleusercontent.com 127.0.0.1:${tlsPort},MAP gemini.google.com 127.0.0.1:${tlsPort}`;
  browser=await chromium.launch({headless:true,args:["--no-proxy-server","--host-resolver-rules="+rules+",MAP * ~NOTFOUND,EXCLUDE 127.0.0.1"]});
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();page.setDefaultTimeout(10000);
  let cspViolation=false;
  page.on("console",msg=>{if(msg.text().includes("form-action"))cspViolation=true;});
  for(const manual of [false,true]) {
    disableAuto=manual;callback=undefined;
    const verifier=crypto.randomBytes(48).toString("base64url"),state=crypto.randomBytes(900).toString("base64url");
    const query=new URLSearchParams({client_id:client.client_id,redirect_uri:redirect,response_type:"code",code_challenge_method:"S256",code_challenge:crypto.createHash("sha256").update(verifier).digest("base64url"),scope:"mcp",state});
    await page.goto(issuer+"/oauth/authorize?"+query);
    await page.getByLabel("本地服务授权密码").fill(password);
    if(manual) {
      await page.getByRole("button",{name:"确认授权"}).click();
      const link=page.getByRole("link",{name:"继续返回 Gemini"});await link.waitFor();
      await Promise.all([page.waitForURL("https://gemini.google.com/oauth-test-complete"),link.click()]);
    } else {
      await Promise.all([page.waitForURL("https://gemini.google.com/oauth-test-complete"),page.getByRole("button",{name:"确认授权"}).click()]);
    }
    if(cspViolation||submittedOrigin!==issuer||!callback?.searchParams.get("code")||callback.searchParams.get("state")!==state)throw new Error("多跳导航、Origin 或 state 校验失败");
    const exchanged=await fetch(backend+"/oauth/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"authorization_code",client_id:client.client_id,client_secret:client.client_secret,code:callback.searchParams.get("code"),code_verifier:verifier,redirect_uri:redirect})});
    if(exchanged.status!==200)throw new Error("浏览器回调后 PKCE 交换失败");
    console.log((manual?"手动返回入口":"自动返回")+"：本站结果页 → Google 回调 → Gemini，多跳导航和 PKCE 均通过。");
  }
  console.log("全部 Google/Gemini 请求已映射到本地 HTTPS 测试服务器，未访问真实账号或用户项目。");
} finally {
  if(browser)await browser.close();
  if(child.exitCode===null){const exited=new Promise(r=>child.once("exit",r));child.kill("SIGTERM");await exited;}
  proxy.closeAllConnections();await new Promise(r=>proxy.close(r));
  for(const dir of [root,path.join(temp,"private")])if(fs.existsSync(dir)){for(const name of fs.readdirSync(dir))fs.unlinkSync(path.join(dir,name));fs.rmdirSync(dir);}
  fs.unlinkSync(key);fs.unlinkSync(cert);fs.rmdirSync(temp);
}
