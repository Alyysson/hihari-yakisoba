const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const url = require("url");

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");
const PRODUCTS_FILE = path.join(DATA_DIR, "products.json");
fs.mkdirSync(DATA_DIR, {recursive:true});

const ADMIN_USER = process.env.ADMIN_USER || "Hikari";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "scrypt$16384$8$1$e/rtOp0MQqpXCOqOQb2JoA==$gVBGRmyT1/XQaLBn02SuUzxjfeLI5tSTZO38q6BTRktSO7eiTzvXiW/V3BxTg0Fvy+pPUf99KcThpcsjb8zI/A==";
const SESSION_SECRET = process.env.SESSION_SECRET || "pEOlo4JbUUBTJ8aOY50B-ml5rBBXJEdfZGSHlDrqBA8j0qS0ALjn7zvJFyLfQZ8W";

const defaultProducts = [
 {id:1,name:"Yakisoba Frango",desc:"Macarrão, frango, legumes selecionados e nosso molho especial.",price:29.90,cat:"Yakisoba",img:"https://images.unsplash.com/photo-1612929633738-8fe44f7ec841?auto=format&fit=crop&w=700&q=85"},
 {id:2,name:"Yakisoba Carne",desc:"Macarrão, carne, legumes selecionados e nosso molho especial.",price:31.90,cat:"Yakisoba",img:"https://images.unsplash.com/photo-1569718212165-3a8278d5f624?auto=format&fit=crop&w=700&q=85"},
 {id:3,name:"Yakisoba Misto",desc:"Macarrão, frango, carne, legumes e nosso molho especial.",price:33.90,cat:"Yakisoba",img:"https://images.unsplash.com/photo-1552611052-33e04de081de?auto=format&fit=crop&w=700&q=85"},
 {id:4,name:"Yakisoba Vegetariano",desc:"Macarrão, legumes selecionados e nosso molho especial.",price:28.90,cat:"Yakisoba",img:"https://images.unsplash.com/photo-1512058564366-18510be2db19?auto=format&fit=crop&w=700&q=85"},
 {id:5,name:"Coca-Cola 350ml",desc:"Lata 350ml.",price:6.00,cat:"Bebidas",img:"https://images.unsplash.com/photo-1554866585-cd94860890b7?auto=format&fit=crop&w=700&q=85"}
];
if(!fs.existsSync(PRODUCTS_FILE)) fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(defaultProducts,null,2));

const sessions = new Map();

function parseCookies(req){
  const out={};
  (req.headers.cookie||"").split(";").forEach(x=>{
    const i=x.indexOf("="); if(i>0) out[x.slice(0,i).trim()]=decodeURIComponent(x.slice(i+1).trim());
  }); return out;
}
function sign(v){return crypto.createHmac("sha256",SESSION_SECRET).update(v).digest("hex")}
function makeSession(){
  const id=crypto.randomBytes(32).toString("hex"), exp=Date.now()+8*60*60*1000;
  const token=id+"."+sign(id);
  sessions.set(id,exp); return {token,exp};
}
function isAdmin(req){
  const token=parseCookies(req).hikari_session; if(!token) return false;
  const [id,sig]=token.split(".");
  if(!id||!sig||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(sign(id)))) return false;
  const exp=sessions.get(id); if(!exp||exp<Date.now()){sessions.delete(id);return false}
  return true;
}
function verifyPassword(input, stored){
  const parts=stored.split("$"); if(parts.length!==6||parts[0]!=="scrypt") return false;
  const n=+parts[1],r=+parts[2],p=+parts[3],salt=Buffer.from(parts[4],"base64"),expected=Buffer.from(parts[5],"base64");
  const got=crypto.scryptSync(input,salt,expected.length,{N:n,r,p});
  return got.length===expected.length && crypto.timingSafeEqual(got,expected);
}
function readProducts(){return JSON.parse(fs.readFileSync(PRODUCTS_FILE,"utf8"))}
function writeProducts(p){fs.writeFileSync(PRODUCTS_FILE,JSON.stringify(p,null,2))}
function send(res,status,data,headers={}){
  res.writeHead(status,{"Content-Type":"application/json; charset=utf-8",...headers});
  res.end(JSON.stringify(data));
}
function body(req){
  return new Promise((resolve,reject)=>{
    let b=""; req.on("data",c=>{b+=c;if(b.length>8e6) req.destroy()}); req.on("end",()=>{try{resolve(b?JSON.parse(b):{})}catch(e){reject(e)}}); req.on("error",reject);
  });
}
function cleanProduct(x,id){
  return {id:id||Number(x.id)||Date.now(),name:String(x.name||"").trim().slice(0,100),desc:String(x.desc||"").trim().slice(0,500),price:Number(x.price)||0,cat:String(x.cat||"Yakisoba").slice(0,40),img:String(x.img||"").slice(0,4_000_000)};
}
const mime={".html":"text/html; charset=utf-8",".css":"text/css",".js":"text/javascript",".json":"application/json",".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".svg":"image/svg+xml"};

const server=http.createServer(async (req,res)=>{
  try{
    const u=url.parse(req.url,true);
    if(req.method==="POST" && u.pathname==="/api/login"){
      const b=await body(req);
      if(String(b.username)===ADMIN_USER && verifyPassword(String(b.password||""),ADMIN_PASSWORD_HASH)){
        const s=makeSession();
        send(res,200,{ok:true},{ "Set-Cookie":`hikari_session=${encodeURIComponent(s.token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`});
      }else send(res,401,{error:"Credenciais inválidas"});
      return;
    }
    if(req.method==="POST" && u.pathname==="/api/logout"){
      const c=parseCookies(req), t=c.hikari_session; if(t) sessions.delete((t||"").split(".")[0]);
      send(res,200,{ok:true},{"Set-Cookie":"hikari_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"}); return;
    }
    if(req.method==="GET" && u.pathname==="/api/me"){ if(isAdmin(req)) send(res,200,{authenticated:true,user:ADMIN_USER}); else send(res,401,{authenticated:false}); return; }
    if(req.method==="GET" && u.pathname==="/api/products"){send(res,200,readProducts());return}
    if(u.pathname.startsWith("/api/products")){
      if(!isAdmin(req)){send(res,401,{error:"Não autorizado"});return}
      let products=readProducts(), id=Number(u.pathname.split("/").pop());
      if(req.method==="POST"){
        const p=cleanProduct(await body());
        if(!p.name||p.price<0){send(res,400,{error:"Dados inválidos"});return}
        p.id=products.length?Math.max(...products.map(x=>x.id))+1:1; products.push(p); writeProducts(products); send(res,201,p); return;
      }
      if(req.method==="PUT" && id){
        const i=products.findIndex(x=>x.id===id); if(i<0){send(res,404,{error:"Produto não encontrado"});return}
        const p=cleanProduct(await body(),id); if(!p.name||p.price<0){send(res,400,{error:"Dados inválidos"});return}
        products[i]=p; writeProducts(products); send(res,200,p); return;
      }
      if(req.method==="DELETE" && id){
        const next=products.filter(x=>x.id!==id); if(next.length===products.length){send(res,404,{error:"Produto não encontrado"});return}
        writeProducts(next); send(res,200,{ok:true}); return;
      }
    }
    let filePath=u.pathname==="/" ? path.join(__dirname,"public","index.html") : path.join(__dirname,"public",u.pathname);
    if(!filePath.startsWith(path.join(__dirname,"public"))){res.writeHead(403);res.end("Forbidden");return}
    if(fs.existsSync(filePath)&&fs.statSync(filePath).isFile()){
      const ext=path.extname(filePath).toLowerCase(); res.writeHead(200,{"Content-Type":mime[ext]||"application/octet-stream"}); fs.createReadStream(filePath).pipe(res); return;
    }
    res.writeHead(404);res.end("Not found");
  }catch(e){console.error(e);send(res,500,{error:"Erro interno"})}
});
server.listen(PORT,()=>console.log(`Hikari rodando em http://localhost:${PORT}`));
