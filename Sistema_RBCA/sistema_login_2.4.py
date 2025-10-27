# ============================================
# RBAC simple con UI (según croquis propuesto)
# ============================================
# POO + SOLID + Patrones (marcados en comentarios):
# - SRP: servicios separados (auth, autoriz., gestión, auditoría, hash, tokens)
# - OCP/DIP/ISP: contratos para hash, tokens, estrategia de autorización; inyección en SistemaRBAC
# - Strategy: autorización (RoleOnly / MixedOverride)
# - Repository: repos de usuarios, roles, accesos
# - Observer: auditoría notifica a la UI
# - Singleton: fachada del sistema
# - Herencia/Polimorfismo: UsuarioTemporal (ejemplo)

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import List, Optional, Dict, Set, Protocol, runtime_checkable, Tuple
from datetime import datetime, timedelta
from enum import Enum
import hashlib, os, uuid, random, string

# ------------------ Dominio ------------------

class NivelEvento(Enum):
    INFO="INFO"; WARNING="WARNING"; ERROR="ERROR"

# [POO] Evento de auditoría
class EventoAuditoria:
    def __init__(self, usuario: str, accion: str, resultado: str, nivel: NivelEvento, detalles: str = ""):
        self.ts = datetime.now(); self.usuario = usuario
        self.accion = accion; self.resultado = resultado
        self.nivel = nivel; self.detalles = detalles
    def linea(self) -> str:
        det = f" | {self.detalles}" if self.detalles else ""
        return f"[{self.ts:%Y-%m-%d %H:%M:%S}] [{self.nivel.value}] {self.usuario} :: {self.accion} -> {self.resultado}{det}"

# [POO] Acceso/permiso (nombre amigable)
class Acceso:
    def __init__(self, codigo: str, nombre: str, modulo: str):
        self._codigo = codigo; self._nombre = nombre; self._modulo = modulo
    def codigo(self): return self._codigo
    def nombre(self): return self._nombre
    def modulo(self): return self._modulo
    def __hash__(self): return hash(self._codigo)
    def __eq__(self, o): return isinstance(o, Acceso) and o._codigo == self._codigo

# [POO] Rol
class Rol:
    def __init__(self, codigo: str, nombre: str):
        self._codigo=codigo; self._nombre=nombre; self._accesos:Set[Acceso]=set()
    def codigo(self): return self._codigo
    def nombre(self): return self._nombre
    def accesos(self): return set(self._accesos)
    def agregar(self, a: Acceso): self._accesos.add(a)
    def quitar(self, a: Acceso): self._accesos.discard(a)
    def tiene(self, cod:str)->bool: return any(a.codigo()==cod for a in self._accesos)

# [POO] Usuario
class Usuario:
    def __init__(self, usuario:str, hash_clave:str, sal:str, nombre:str, email:str):
        self._u=usuario; self._h=hash_clave; self._s=sal; self._n=nombre; self._e=email
        self._roles:List[Rol]=[]; self._directos:Set[Acceso]=set()
        self._activo=True; self._intentos=0
    def usuario(self): return self._u
    def nombre(self): return self._n
    def email(self): return self._e
    def activo(self): return self._activo
    def set_activo(self,v:bool): self._activo=v
    def roles(self): return list(self._roles)
    def agregar_rol(self,r:Rol): 
        if r and r not in self._roles:
            self._roles.append(r)
    def agregar_directo(self,a:Acceso): self._directos.add(a)
    def quitar_directo(self,a:Acceso): self._directos.discard(a)
    def todos_accesos(self)->Set[Acceso]:
        s=set(self._directos)
        for r in self._roles: s |= r.accesos()
        return s
    def tiene(self,cod:str)->bool:
        if any(a.codigo()==cod for a in self._directos): return True
        return any(r.tiene(cod) for r in self._roles)
    # seguridad (hash + intentos)
    def _hash(self): return self._h
    def _sal(self): return self._s
    def _set_hash(self,h,s): 
        self._h=h; self._s=s; self._intentos=0
    def intentos(self): return self._intentos
    def inc(self): self._intentos+=1; return self._intentos
    def reset(self): self._intentos=0

# [Herencia + Polimorfismo] Ejemplo
class UsuarioTemporal(Usuario):
    def __init__(self,*args, dias:int=7, **kwargs):
        super().__init__(*args, **kwargs); self._expira=datetime.now()+timedelta(days=dias)
    def activo(self)->bool: return super().activo() and datetime.now()<=self._expira

# ------------------ Interfaces (ISP) ------------------

@runtime_checkable
class IHashService(Protocol):
    def generar_sal(self)->str: ...
    def hash(self, clave:str, sal:str)->str: ...
    def verifica(self, clave:str, sal:str, esperado:str)->bool: ...

@runtime_checkable
class ITokenService(Protocol):
    def emitir(self, sujeto:str, ttl:int=1800)->str: ...
    def verificar(self, token:str)->Tuple[bool,Optional[str]]: ...
    def revocar(self, token:str)->None: ...

@runtime_checkable
class IAuthorizationStrategy(Protocol):
    def has_access(self, usuario:Usuario, acceso_cod:str)->bool: ...

# ------------------ Infra / Servicios ------------------

# [SRP] Hash (demo)
class HashService(IHashService):
    def generar_sal(self)->str: return os.urandom(16).hex()
    def hash(self, clave:str, sal:str)->str: return hashlib.sha256((sal+clave).encode()).hexdigest()
    def verifica(self, clave:str, sal:str, esperado:str)->bool: return self.hash(clave,sal)==esperado

# [SRP] Tokens (simples)
class TokenService(ITokenService):
    def __init__(self): self._exp:Dict[str,datetime]={}; self._sub:Dict[str,str]={}; self._rev=set()
    def emitir(self,sujeto:str,ttl:int=1800)->str:
        t=str(uuid.uuid4()); self._exp[t]=datetime.now()+timedelta(seconds=ttl); self._sub[t]=sujeto; return t
    def verificar(self,t:str)->Tuple[bool,Optional[str]]:
        if t in self._rev: return False,None
        e=self._exp.get(t); 
        if not e or datetime.now()>e: return False,None
        return True,self._sub[t]
    def revocar(self,t:str)->None: self._rev.add(t)

# [Strategy] Autorización
class MixedOverrideStrategy(IAuthorizationStrategy):
    def has_access(self, usuario:Usuario, acceso_cod:str)->bool: return usuario.tiene(acceso_cod)

# ------------------ Repos (Repository) ------------------

class RepoAccesos:
    def __init__(self):
        self._map:Dict[str,Acceso]={}
        self._seed()
    def _seed(self):
        base=[
            Acceso("documentos.ver","Ver documentos","documentos"),
            Acceso("documentos.crear","Crear documentos","documentos"),
            Acceso("documentos.editar","Editar documentos","documentos"),
            Acceso("documentos.eliminar","Eliminar documentos","documentos"),
            Acceso("reportes.ver","Ver reportes","reportes"),
            Acceso("reportes.generar","Generar reportes","reportes"),
            Acceso("usuarios.ver","Ver usuarios","usuarios"),
            Acceso("usuarios.crear","Crear usuarios","usuarios"),
            Acceso("usuarios.editar","Editar usuarios/contraseñas","usuarios"),
            Acceso("usuarios.bloquear","Bloquear usuarios","usuarios"),
            Acceso("roles.ver","Ver roles","roles"),
            Acceso("roles.gestionar","Gestionar roles/accesos","roles"),
            Acceso("auditoria.ver","Ver auditoría","auditoria"),
        ]
        for a in base: self._map[a.codigo()]=a
    def por_codigo(self,c:str)->Optional[Acceso]: return self._map.get(c)
    def todos(self)->List[Acceso]: return list(self._map.values())

class RepoRoles:
    def __init__(self, acc:RepoAccesos):
        self._r:Dict[str,Rol]={}; self._acc=acc; self._seed()
    def _seed(self):
        def rol(c,n,lista): 
            r=Rol(c,n); [r.agregar(self._acc.por_codigo(x)) for x in lista if self._acc.por_codigo(x)]; self._r[c]=r
        rol("personal","Personal",["documentos.ver"])
        rol("jefe","Jefe de Área",["documentos.ver","documentos.editar"])
        rol("gerente","Gerente",["documentos.ver","reportes.generar"])
        rol("director","Director",["documentos.ver","reportes.generar"])
        rol("supervisor","Supervisor",["documentos.ver","documentos.eliminar"])
        rol("admin","Administrador del Sistema",[a.codigo() for a in self._acc.todos()])
    def por_codigo(self,c)->Optional[Rol]: return self._r.get(c)
    def todos(self)->List[Rol]: return list(self._r.values())

class RepoUsuarios:
    def __init__(self): self._u:Dict[str,Usuario]={}
    def existe(self,u:str)->bool: return u in self._u
    def guardar(self,usr:Usuario)->None: self._u[usr.usuario()]=usr
    def por_usuario(self,u:str)->Optional[Usuario]: return self._u.get(u)
    def todos(self)->List[Usuario]: return list(self._u.values())

# ------------------ Servicios (Aplicación) ------------------

# [Observer] Auditoría (notifica a UI)
class ServicioAuditoria:
    def __init__(self): self._ev:List[EventoAuditoria]=[]; self._obs=[]
    def observar(self,obs): self._obs.append(obs)
    def registrar(self,usuario:str,accion:str,resultado:str,nivel:NivelEvento,detalles:str=""):
        ev=EventoAuditoria(usuario,accion,resultado,nivel,detalles); self._ev.append(ev)
        for o in self._obs:
            if hasattr(o,"actualizar_log"): o.actualizar_log(ev)
    def ultimos(self,n:int=200)->List[EventoAuditoria]: return self._ev[-n:]

# [SRP] Autenticación
class ServicioAutenticacion:
    def __init__(self, repo_u:RepoUsuarios, hashsvc:IHashService, tokens:ITokenService, aud:ServicioAuditoria):
        self._u=repo_u; self._h=hashsvc; self._t=tokens; self._aud=aud
    def registrar_basico(self, usuario:str, clave:str, nombre:str, email:str)->Usuario:
        sal=self._h.generar_sal(); ha=self._h.hash(clave,sal)
        u=Usuario(usuario,ha,sal,nombre,email); self._u.guardar(u); return u
    def restablecer_clave(self, admin:str, usuario:str, nueva:str)->Tuple[bool,str]:
        u=self._u.por_usuario(usuario); 
        if not u: return False,"Usuario inexistente."
        sal=self._h.generar_sal(); u._set_hash(self._h.hash(nueva,sal),sal)
        self._aud.registrar(admin,"Restablecer contraseña","Exitoso",NivelEvento.WARNING,f"objetivo={usuario}")
        return True,"Contraseña actualizada."
    def autenticar(self, usuario:str, clave:str)->Tuple[Optional[Usuario],Optional[str],Optional[str]]:
        u=self._u.por_usuario(usuario)
        if not u or not u.activo():
            self._aud.registrar(usuario,"Login","Fallido (inexistente/inactivo)",NivelEvento.ERROR)
            return None,None,"Usuario o contraseña incorrectos."
        if u.intentos()>=3:
            self._aud.registrar(usuario,"Login","Fallido (bloqueado)",NivelEvento.ERROR)
            return None,None,"Usuario bloqueado por intentos fallidos."
        if self._h.verifica(clave,u._sal(),u._hash()):
            u.reset(); token=self._t.emitir(u.usuario())
            self._aud.registrar(usuario,"Login","Exitoso",NivelEvento.INFO)
            return u,token,None
        else:
            intento=u.inc()
            self._aud.registrar(usuario,"Login",f"Fallido (intento {intento}/3)",NivelEvento.WARNING)
            return None,None,"Usuario o contraseña incorrectos."
    def logout(self, token:str, usuario:str):
        self._t.revocar(token); self._aud.registrar(usuario,"Logout","Exitoso",NivelEvento.INFO)

# [SRP + Strategy] Autorización
class ServicioAutorizacion:
    def __init__(self, estrategia:IAuthorizationStrategy, aud:ServicioAuditoria):
        self._e=estrategia; self._aud=aud
    def validar(self, u:Usuario, acceso_cod:str)->bool:
        ok=self._e.has_access(u,acceso_cod)
        self._aud.registrar(u.usuario(),"Autorizar","Permitido" if ok else "Denegado",NivelEvento.INFO,acceso_cod)
        return ok

# [SRP] Gestión
class ServicioGestion:
    def __init__(self, repo_u:RepoUsuarios, repo_r:RepoRoles, repo_a:RepoAccesos, aud:ServicioAuditoria):
        self._u=repo_u; self._r=repo_r; self._a=repo_a; self._aud=aud
    def crear_usuario(self, actor:str, auth:ServicioAutenticacion, usuario:str, clave:str, nombre:str, email:str, rol:str, accesos:list)->Tuple[bool,str]:
        if self._u.existe(usuario):
            self._aud.registrar(actor,"Crear usuario","Fallido (existe)",NivelEvento.WARNING,usuario)
            return False,"El usuario ya existe."
        u=auth.registrar_basico(usuario,clave,nombre,email)
        rr=self._r.por_codigo(rol)
        if rr: u.agregar_rol(rr)
        for cod in accesos:
            a=self._a.por_codigo(cod)
            if a: u.agregar_directo(a)
        self._aud.registrar(actor,"Crear usuario","Exitoso",NivelEvento.INFO,f"{usuario} rol={rol} accesos={len(accesos)}")
        return True,"Usuario creado."
    def dar_acceso_directo(self, actor:str, usuario:str, acceso_cod:str)->Tuple[bool,str]:
        u=self._u.por_usuario(usuario); a=self._a.por_codigo(acceso_cod)
        if not u or not a: return False,"Usuario/acceso inexistente."
        u.agregar_directo(a); self._aud.registrar(actor,"Dar acceso","Exitoso",NivelEvento.INFO,f"{usuario} += {acceso_cod}")
        return True,"Acceso otorgado."
    def quitar_acceso_directo(self, actor:str, usuario:str, acceso_cod:str)->Tuple[bool,str]:
        u=self._u.por_usuario(usuario); a=self._a.por_codigo(acceso_cod)
        if not u or not a: return False,"Usuario/acceso inexistente."
        u.quitar_directo(a); self._aud.registrar(actor,"Quitar acceso","Exitoso",NivelEvento.INFO,f"{usuario} -= {acceso_cod}")
        return True,"Acceso quitado."
    # lecturas
    def usuarios(self)->List[Usuario]: return self._u.todos()
    def roles(self)->List[Rol]: return self._r.todos()
    def accesos(self)->List[Acceso]: return self._a.todos()

# ------------------ Fachada (Singleton) ------------------

class SistemaRBAC:
    _inst=None
    def __new__(cls):
        if not cls._inst: cls._inst=super().__new__(cls)
        return cls._inst
    def __init__(self):
        if getattr(self,"_init",False): return
        self.repoAcc=RepoAccesos(); self.repoRol=RepoRoles(self.repoAcc); self.repoUsr=RepoUsuarios()
        self.aud=ServicioAuditoria()
        self.hash=HashService(); self.tokens=TokenService()
        self.auth=ServicioAutenticacion(self.repoUsr,self.hash,self.tokens,self.aud)
        self.authz=ServicioAutorizacion(MixedOverrideStrategy(),self.aud)
        self.gestion=ServicioGestion(self.repoUsr,self.repoRol,self.repoAcc,self.aud)
        self._seed()
        self._init=True
    def _seed(self):
        datos=[
            ("carlos.mendez","1230","Carlos Méndez","carlos@empresa.com","personal"),
            ("sofia.ramirez","1230","Sofía Ramírez","sofia@empresa.com","admin"),
            ("martin.lopez","1230","Martín López","martin@empresa.com","gerente"),
            ("laura.garcia","1230","Laura García","laura@empresa.com","director"),
            ("diego.fernandez","1230","Diego Fernández","diego@empresa.com","supervisor"),
            ("ana.torres","1230","Ana Torres","ana@empresa.com","jefe"),
        ]
        for u,p,n,e,r in datos:
            usr=self.auth.registrar_basico(u,p,n,e); rol=self.repoRol.por_codigo(r)
            if rol: usr.agregar_rol(rol)

# ------------------ UI (según croquis) ------------------

class AppLogin:
    # 🎨 COLORES MEJORADOS
    BG="#0A1628"; CARD="#0F2847"; TEXT="#F1F5F9"; DIM="#94A3B8"; PRI="#3B82F6"; PRI_HOVER="#2563EB"; ACCENT="#06B6D4"; SHADOW="#060F1A"
    
    def __init__(self, sis:SistemaRBAC):
        self.sis=sis
        self.root=tk.Tk(); self.root.title("Login - Sistema RBAC"); self.root.configure(bg=self.BG)
        self.root.geometry("460x460")
        # Centrar ventana
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 460) // 2
        y = (self.root.winfo_screenheight() - 460) // 2
        self.root.geometry(f"+{x}+{y}")
        self._armar()
    
    def _armar(self):
        # 🎨 Frame con efecto de profundidad (sombra)
        shadow=tk.Frame(self.root,bg=self.SHADOW); shadow.place(relx=.5,rely=.52,anchor="center",width=390,height=370)
        card=tk.Frame(self.root,bg=self.CARD,bd=2,relief="flat",highlightbackground=self.ACCENT,highlightthickness=1)
        card.place(relx=.5,rely=.5,anchor="center",width=380,height=360)
        
        # 🎨 Gradiente visual (simulado con frames)
        top_accent=tk.Frame(card,bg=self.ACCENT,height=3); top_accent.pack(fill="x")
        
        # 🎨 Iconos y títulos con color accent
        tk.Label(card,text="🔐",font=("Segoe UI",38),bg=self.CARD,fg=self.ACCENT).pack(pady=(18,6))
        tk.Label(card,text="Sistema RBAC",font=("Segoe UI",20,"bold"),fg=self.TEXT,bg=self.CARD).pack()
        tk.Label(card,text="Control de Acceso Basado en Roles",font=("Segoe UI",9),fg=self.DIM,bg=self.CARD).pack(pady=(2,0))
        
        form=tk.Frame(card,bg=self.CARD); form.pack(padx=26,pady=14,fill="x")
        
        # 🎨 Campo Usuario con estilo mejorado
        tk.Label(form,text="Usuario",fg=self.TEXT,bg=self.CARD,font=("Segoe UI",10,"bold")).pack(anchor="w",pady=(4,2))
        self.e_user=tk.Entry(form,font=("Segoe UI",12),bg="#1E3A5F",fg=self.TEXT,insertbackground=self.ACCENT,relief="flat",bd=0)
        self.e_user.pack(fill="x",ipady=8,pady=2)
        
        # 🎨 Campo Contraseña con estilo mejorado
        tk.Label(form,text="Contraseña",fg=self.TEXT,bg=self.CARD,font=("Segoe UI",10,"bold")).pack(anchor="w",pady=(12,2))
        self.e_pass=tk.Entry(form,show="●",font=("Segoe UI",12),bg="#1E3A5F",fg=self.TEXT,insertbackground=self.ACCENT,relief="flat",bd=0)
        self.e_pass.pack(fill="x",ipady=8,pady=2)
        
        self.lbl=tk.Label(card,text="",fg="#FCA5A5",bg=self.CARD,font=("Segoe UI",9)); self.lbl.pack(pady=4)
        
        # 🎨 Botón mejorado con hover
        btn_login=tk.Button(card,text="INICIAR SESIÓN",bg=self.PRI,fg="white",bd=0,font=("Segoe UI",11,"bold"),cursor="hand2",command=self._login,activebackground=self.PRI_HOVER,relief="flat")
        btn_login.pack(pady=8,ipadx=12,ipady=10)
        btn_login.bind("<Enter>", lambda e: btn_login.config(bg=self.PRI_HOVER))
        btn_login.bind("<Leave>", lambda e: btn_login.config(bg=self.PRI))
        
        tk.Label(card,text="Usuarios: carlos.mendez, sofia.ramirez, martin.lopez\nContraseña: 1230",fg=self.DIM,bg=self.CARD,wraplength=320,justify="center",font=("Segoe UI",8)).pack(pady=(6,12))
        
        self.root.bind("<Return>", lambda e: self._login())
        self.e_user.focus()
    
    def _login(self):
        u=self.e_user.get().strip(); p=self.e_pass.get().strip()
        if not u or not p:
            self.lbl.config(text="Ingresá usuario y contraseña."); return
        usr, tok, err = self.sis.auth.autenticar(u,p)
        if usr:
            self.root.destroy()
            AppMain(self.sis, usr, tok).run()
        else:
            self.lbl.config(text=err or "Usuario o contraseña incorrectos.")
            self.e_pass.delete(0, tk.END)
    
    def run(self): self.root.mainloop()
    # ------------------ Splash Screen con Animación ------------------

class SplashScreen:
    def __init__(self, callback):
        self.callback = callback
        self.root = tk.Tk()
        self.root.title("Cargando...")
        self.root.configure(bg="#0A1628")
        self.root.geometry("600x400")
        self.root.overrideredirect(True)  # Sin bordes
        
        # Centrar ventana
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 600) // 2
        y = (self.root.winfo_screenheight() - 400) // 2
        self.root.geometry(f"+{x}+{y}")
        
        # Canvas para la animación
        self.canvas = tk.Canvas(self.root, width=600, height=400, bg="#0A1628", highlightthickness=0)
        self.canvas.pack()
        
        # Dibujar fondo con gradiente simulado
        for i in range(20):
            color = self._gradient_color("#0A1628", "#0F2847", i/20)
            self.canvas.create_rectangle(0, i*20, 600, (i+1)*20, fill=color, outline="")
        
        # Texto de carga
        self.canvas.create_text(300, 320, text="Sistema RBAC", 
                               font=("Segoe UI", 28, "bold"), fill="#F1F5F9")
        self.canvas.create_text(300, 360, text="Cargando...", 
                               font=("Segoe UI", 12), fill="#94A3B8")
        
        # Águila (forma simplificada con polígonos)
        self.eagle_x = -100
        self.eagle_y = 150
        self.eagle_parts = []
        self._create_eagle()
        
        # Iniciar animación
        self.animate()
        
        # Auto-cerrar después de 3 segundos
        self.root.after(3000, self.close)
    
    def _gradient_color(self, color1, color2, ratio):
        """Interpolar entre dos colores"""
        c1 = int(color1[1:3], 16), int(color1[3:5], 16), int(color1[5:7], 16)
        c2 = int(color2[1:3], 16), int(color2[3:5], 16), int(color2[5:7], 16)
        r = int(c1[0] + (c2[0] - c1[0]) * ratio)
        g = int(c1[1] + (c2[1] - c1[1]) * ratio)
        b = int(c1[2] + (c2[2] - c1[2]) * ratio)
        return f"#{r:02x}{g:02x}{b:02x}"
    
    def _create_eagle(self):
        """Crear águila estilizada"""
        # Cuerpo
        body = self.canvas.create_oval(
            self.eagle_x, self.eagle_y + 20,
            self.eagle_x + 60, self.eagle_y + 80,
            fill="#06B6D4", outline="#3B82F6", width=2
        )
        
        # Cabeza
        head = self.canvas.create_oval(
            self.eagle_x + 15, self.eagle_y,
            self.eagle_x + 45, self.eagle_y + 35,
            fill="#3B82F6", outline="#06B6D4", width=2
        )
        
        # Ala izquierda (arriba)
        wing_left1 = self.canvas.create_polygon(
            self.eagle_x, self.eagle_y + 40,
            self.eagle_x - 50, self.eagle_y + 10,
            self.eagle_x - 30, self.eagle_y + 50,
            fill="#2563EB", outline="#06B6D4", width=2
        )
        
        # Ala derecha (abajo)
        wing_right1 = self.canvas.create_polygon(
            self.eagle_x + 60, self.eagle_y + 40,
            self.eagle_x + 110, self.eagle_y + 70,
            self.eagle_x + 90, self.eagle_y + 50,
            fill="#1E40AF", outline="#06B6D4", width=2
        )
        
        # Pico
        beak = self.canvas.create_polygon(
            self.eagle_x + 45, self.eagle_y + 18,
            self.eagle_x + 55, self.eagle_y + 20,
            self.eagle_x + 45, self.eagle_y + 22,
            fill="#F59E0B", outline=""
        )
        
        # Ojo
        eye = self.canvas.create_oval(
            self.eagle_x + 32, self.eagle_y + 15,
            self.eagle_x + 38, self.eagle_y + 21,
            fill="#FCD34D", outline=""
        )
        
        self.eagle_parts = [body, head, wing_left1, wing_right1, beak, eye]
        
        # Alas secundarias para efecto de aleteo
        self.wing_left2 = self.canvas.create_polygon(
            self.eagle_x, self.eagle_y + 40,
            self.eagle_x - 40, self.eagle_y + 20,
            self.eagle_x - 25, self.eagle_y + 55,
            fill="#3B82F6", outline="#06B6D4", width=2, state="hidden"
        )
        
        self.wing_right2 = self.canvas.create_polygon(
            self.eagle_x + 60, self.eagle_y + 40,
            self.eagle_x + 100, self.eagle_y + 60,
            self.eagle_x + 85, self.eagle_y + 45,
            fill="#2563EB", outline="#06B6D4", width=2, state="hidden"
        )
        
        self.wing_state = 0
    
    def animate(self):
        """Animar el águila volando de izquierda a derecha"""
        # Mover águila
        self.eagle_x += 8
        
        # Movimiento ondulante (arriba/abajo)
        import math
        self.eagle_y = 150 + math.sin(self.eagle_x / 30) * 20
        
        # Mover todas las partes
        for part in self.eagle_parts:
            self.canvas.moveto(part, self.eagle_x, self.eagle_y)
        
        # Efecto de aleteo (alternar alas)
        self.wing_state = (self.wing_state + 1) % 10
        if self.wing_state < 5:
            self.canvas.itemconfig(self.wing_left2, state="hidden")
            self.canvas.itemconfig(self.wing_right2, state="hidden")
        else:
            self.canvas.itemconfig(self.wing_left2, state="normal")
            self.canvas.itemconfig(self.wing_right2, state="normal")
            self.canvas.moveto(self.wing_left2, self.eagle_x, self.eagle_y)
            self.canvas.moveto(self.wing_right2, self.eagle_x, self.eagle_y)
        
        # Continuar animación si el águila no salió de la pantalla
        if self.eagle_x < 700:
            self.root.after(30, self.animate)
    
    def close(self):
        """Cerrar splash y llamar al callback"""
        self.root.destroy()
        self.callback()
    
    def run(self):
        self.root.mainloop()
        

class AppMain:
    # 🎨 COLORES MEJORADOS
    BG="#0A1628"; CARD="#0F2847"; TEXT="#F1F5F9"; DIM="#94A3B8"; PRI="#3B82F6"; PRI_HOVER="#2563EB"; OK="#10B981"; DANGER="#EF4444"; ACCENT="#06B6D4"; SHADOW="#020617"
    
    def __init__(self, sis:SistemaRBAC, usr:Usuario, token:str):
        self.sis=sis; self.usr=usr; self.token=token
        self.root=tk.Tk(); self.root.title("Sistema RBAC"); self.root.configure(bg=self.BG)
        self.root.geometry("1080x640"); self.root.resizable(False,False)
        # Centrar ventana
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 1080) // 2
        y = (self.root.winfo_screenheight() - 640) // 2
        self.root.geometry(f"+{x}+{y}")
        self.sis.aud.observar(self)
        self._armar()
    
    def _armar(self):
        # 🎨 Panel izquierdo con sombra
        left_shadow=tk.Frame(self.root,bg=self.SHADOW); left_shadow.place(x=14,y=14,width=280,height=616)
        left=tk.Frame(self.root,bg=self.CARD,bd=2,relief="flat",highlightbackground=self.ACCENT,highlightthickness=1,width=280)
        left.pack(side="left",fill="y",padx=12,pady=12)
        left.pack_propagate(False)
        
        right=tk.Frame(self.root,bg=self.BG); right.pack(side="left",fill="both",expand=True,padx=(0,12),pady=12)

        # 🎨 Header con gradiente
        header_accent=tk.Frame(left,bg=self.ACCENT,height=3); header_accent.pack(fill="x")
        
        # 🎨 Detalles del usuario con mejor diseño
        tk.Label(left,text="MI PERFIL",font=("Segoe UI",11,"bold"),fg=self.ACCENT,bg=self.CARD).pack(anchor="w",padx=12,pady=(16,2))
        tk.Frame(left,bg=self.ACCENT,height=2).pack(fill="x",padx=12,pady=(0,8))
        
        self._kv(left,"Nombre",self.usr.nombre())
        self._kv(left,"Usuario",self.usr.usuario())
        self._kv(left,"Email",self.usr.email())
        self._kv(left,"Roles",", ".join(r.nombre() for r in self.usr.roles()) or "—",wrap=True)
        
        # 🎨 Botón de cerrar sesión mejorado con hover y emoji
        btn_logout=tk.Button(left,text="🚪 Cerrar sesión",bg=self.DANGER,fg="white",bd=0,font=("Segoe UI",10,"bold"),cursor="hand2",command=self._logout,relief="flat")
        btn_logout.pack(side="bottom",pady=16,padx=12,fill="x",ipady=10)
        btn_logout.bind("<Enter>", lambda e: btn_logout.config(bg="#DC2626"))
        btn_logout.bind("<Leave>", lambda e: btn_logout.config(bg=self.DANGER))
        
        # 🎨 Tabs mejorados con estilos personalizados
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=self.BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.CARD, foreground=self.TEXT, padding=[20,10], font=("Segoe UI",10))
        style.map("TNotebook.Tab", background=[("selected", self.ACCENT)], foreground=[("selected", "white")])
        
        nb=ttk.Notebook(right); nb.pack(fill="both",expand=True)

        # Accesos (siempre visible; solo listado sin funcionalidad)
        tab_acc=tk.Frame(nb,bg=self.BG); nb.add(tab_acc,text="  Accesos  ")
        self._tab_accesos(tab_acc)

        # Gestionar usuarios (solo admin del sistema)
        if any(r.codigo()=="admin" for r in self.usr.roles()):
            tab_gest=tk.Frame(nb,bg=self.BG); nb.add(tab_gest,text="  Gestionar usuarios  ")
            self._tab_gestion(tab_gest)

        # Auditoría (si tiene acceso auditoria.ver)
        if self.sis.authz.validar(self.usr,"auditoria.ver"):
            tab_aud=tk.Frame(nb,bg=self.BG); nb.add(tab_aud,text="  Auditoría  ")
            self._tab_auditoria(tab_aud)

    def _kv(self,parent,k,v,wrap=False):
        box=tk.Frame(parent,bg=self.CARD); box.pack(fill="x",padx=12,pady=6)
        tk.Label(box,text=k,fg=self.DIM,bg=self.CARD,font=("Segoe UI",10,"bold")).pack(anchor="w")
        tk.Label(box,text=v,fg=self.TEXT,bg=self.CARD,wraplength=250 if wrap else 0,justify="left").pack(anchor="w")

    # --------- pestaña Accesos (solo lista) ----------
    def _tab_accesos(self, parent):
        card=tk.Frame(parent,bg=self.CARD,bd=1,relief="solid"); card.pack(fill="both",expand=True,padx=8,pady=8)
        tk.Label(card,text="ACCESOS",font=("Segoe UI",12,"bold"),fg=self.TEXT,bg=self.CARD).pack(anchor="w",padx=10,pady=10)
        cols=("modulo","acceso")
        tv=ttk.Treeview(card,columns=cols,show="headings",height=18)
        for c in cols: tv.heading(c,text=c.capitalize()); tv.column(c,width=220 if c=="modulo" else 720)
        tv.pack(fill="both",expand=True,padx=10,pady=(0,10))
        accesos=sorted(self.usr.todos_accesos(), key=lambda a:(a.modulo(),a.nombre()))
        for a in accesos: tv.insert("", "end", values=(a.modulo().capitalize(), a.nombre()))

    # --------- pestaña Gestionar usuarios (solo admin) ----------
    def _tab_gestion(self, parent):
        # parte superior: crear usuario
        card=tk.Frame(parent,bg=self.CARD,bd=1,relief="solid"); card.pack(fill="x",padx=8,pady=8)
        tk.Label(card,text="GESTIONAR USUARIOS",font=("Segoe UI",12,"bold"),fg=self.TEXT,bg=self.CARD).grid(row=0,column=0,columnspan=8,sticky="w",padx=10,pady=10)

        tk.Label(card,text="Usuario",fg=self.TEXT,bg=self.CARD).grid(row=1,column=0,sticky="e",padx=8,pady=4)
        tk.Label(card,text="Nombre",fg=self.TEXT,bg=self.CARD).grid(row=1,column=2,sticky="e",padx=8,pady=4)
        tk.Label(card,text="Email",fg=self.TEXT,bg=self.CARD).grid(row=2,column=0,sticky="e",padx=8,pady=4)
        tk.Label(card,text="Contraseña",fg=self.TEXT,bg=self.CARD).grid(row=2,column=2,sticky="e",padx=8,pady=4)

        self.nu_user=tk.Entry(card); self.nu_name=tk.Entry(card); self.nu_mail=tk.Entry(card); self.nu_pass=tk.Entry(card,show="●")
        self.nu_user.grid(row=1,column=1,padx=6,pady=4); self.nu_name.grid(row=1,column=3,padx=6,pady=4)
        self.nu_mail.grid(row=2,column=1,padx=6,pady=4); self.nu_pass.grid(row=2,column=3,padx=6,pady=4)

        tk.Label(card,text="Rol",fg=self.TEXT,bg=self.CARD).grid(row=3,column=0,sticky="e",padx=8,pady=4)
        self.nu_rol=ttk.Combobox(card, values=[r.codigo() for r in self.sis.gestion.roles()], width=20)
        self.nu_rol.grid(row=3,column=1,sticky="w",padx=6,pady=4)

        # Accesos directos (checklist)
        tk.Label(card,text="Accesos directos (opcional)",fg=self.TEXT,bg=self.CARD).grid(row=4,column=0,sticky="ne",padx=8,pady=4)
        self._vars_acc:Dict[str,tk.IntVar]={}
        acc_frame=tk.Frame(card,bg=self.CARD); acc_frame.grid(row=4,column=1,columnspan=3,sticky="w")
        for i,a in enumerate(sorted(self.sis.gestion.accesos(), key=lambda x:x.nombre())):
            v=tk.IntVar(value=0); self._vars_acc[a.codigo()]=v
            tk.Checkbutton(acc_frame,text=a.nombre(),variable=v,bg=self.CARD,fg=self.TEXT,selectcolor="#1F2937").grid(row=i//3,column=i%3,sticky="w",padx=6,pady=2)

        tk.Button(card,text="Crear usuario",bg=self.PRI,fg="white",bd=0,command=self._crear_usuario).grid(row=3,column=3,sticky="e",padx=10,pady=6)

        # tabla + acciones
        box=tk.Frame(parent,bg=self.CARD,bd=1,relief="solid"); box.pack(fill="both",expand=True,padx=8,pady=(0,8))
        cols=("usuario","nombre","email","roles","accesos")
        self.tv=ttk.Treeview(box,columns=cols,show="headings",height=12)
        for c in cols:
            self.tv.heading(c,text=c.capitalize()); self.tv.column(c,width=160 if c!="accesos" else 420)
        self.tv.pack(fill="both",expand=True,padx=10,pady=10)

        bar=tk.Frame(box,bg=self.CARD); bar.pack(anchor="e",padx=10,pady=(0,10))
        tk.Button(bar,text="Dar acceso",bg=self.OK,fg="white",bd=0,command=self._dar_acceso).pack(side="left",padx=6)
        tk.Button(bar,text="Quitar acceso",bg=self.DANGER,fg="white",bd=0,command=self._quitar_acceso).pack(side="left",padx=6)
        tk.Button(bar,text="Restablecer contraseña",bg="#334155",fg="white",bd=0,command=self._reset_pass).pack(side="left",padx=6)

        self._refresh_users()

    def _sel_usuario(self)->Optional[str]:
        it=self.tv.selection()
        if not it: messagebox.showwarning("Aviso","Seleccioná un usuario en la tabla."); return None
        return self.tv.item(it[0],"values")[0]

    def _crear_usuario(self):
        u=self.nu_user.get().strip(); n=self.nu_name.get().strip(); m=self.nu_mail.get().strip(); p=self.nu_pass.get().strip(); r=self.nu_rol.get().strip()
        if not all([u,n,m,p]): messagebox.showwarning("Aviso","Completá usuario, nombre, email y contraseña."); return
        accesos=[cod for cod,var in self._vars_acc.items() if var.get()==1]
        ok,msg=self.sis.gestion.crear_usuario(self.usr.usuario(), self.sis.auth, u,p,n,m,r,accesos)
        if ok:
            for e in (self.nu_user,self.nu_name,self.nu_mail,self.nu_pass): e.delete(0,"end")
            [v.set(0) for v in self._vars_acc.values()]
            self._refresh_users()
            messagebox.showinfo("Crear usuario","Usuario creado exitosamente.")
        else:
            messagebox.showerror("Crear usuario",msg)

    def _dar_acceso(self):
        u=self._sel_usuario()
        if not u: return
        cod=self._pick_acceso("Seleccioná acceso para otorgar")
        if not cod: return
        ok,msg=self.sis.gestion.dar_acceso_directo(self.usr.usuario(),u,cod)
        if ok: self._refresh_users(); messagebox.showinfo("Accesos","Acceso otorgado.")
        else: messagebox.showerror("Accesos",msg)

    def _quitar_acceso(self):
        u=self._sel_usuario()
        if not u: return
        cod=self._pick_acceso("Seleccioná acceso para quitar")
        if not cod: return
        ok,msg=self.sis.gestion.quitar_acceso_directo(self.usr.usuario(),u,cod)
        if ok: self._refresh_users(); messagebox.showinfo("Accesos","Acceso quitado.")
        else: messagebox.showerror("Accesos",msg)

    def _reset_pass(self):
        u=self._sel_usuario()
        if not u: return
        temp = self._gen_pass()
        ok,msg=self.sis.auth.restablecer_clave(self.usr.usuario(),u,temp)
        if ok: messagebox.showinfo("Restablecer","Nueva contraseña temporal: "+temp+"\nComunicala de forma segura.")
        else: messagebox.showerror("Restablecer",msg)

    def _pick_acceso(self, title:str)->Optional[str]:
        # diálogo simple con combobox
        win=tk.Toplevel(self.root); win.title(title); win.configure(bg=self.BG)
        tk.Label(win,text=title,fg=self.TEXT,bg=self.BG).pack(padx=10,pady=10)
        cb=ttk.Combobox(win,values=[a.codigo()+" — "+a.nombre() for a in sorted(self.sis.gestion.accesos(),key=lambda x:x.nombre())],width=60)
        cb.pack(padx=10,pady=6); cb.focus_set()
        out={"cod":None}
        def ok():
            sel=cb.get().split(" — ")[0] if cb.get() else ""
            out["cod"]=sel if self._valida_acceso(sel) else None
            win.destroy()
        ttk.Button(win,text="Aceptar",command=ok).pack(pady=10)
        win.grab_set(); self.root.wait_window(win)
        return out["cod"]
    
    def _valida_acceso(self,cod:str)->bool:
        return any(a.codigo()==cod for a in self.sis.gestion.accesos())

    def _gen_pass(self,n=10)->str:
        chars=string.ascii_letters+string.digits
        return "".join(random.choice(chars) for _ in range(n))

    def _refresh_users(self):
        for i in self.tv.get_children(): self.tv.delete(i)
        for u in self.sis.gestion.usuarios():
            roles=", ".join(r.nombre() for r in u.roles()) or "—"
            accesos=", ".join(sorted(a.nombre() for a in u.todos_accesos())) or "—"
            self.tv.insert("", "end", values=(u.usuario(),u.nombre(),u.email(),roles,accesos))

    # ---------- pestaña Auditoría ----------
    def _tab_auditoria(self,parent):
        card=tk.Frame(parent,bg=self.CARD,bd=1,relief="solid"); card.pack(fill="both",expand=True,padx=8,pady=8)
        tk.Label(card,text="AUDITORÍA",font=("Segoe UI",12,"bold"),fg=self.TEXT,bg=self.CARD).pack(anchor="w",padx=10,pady=10)
        self.txt=scrolledtext.ScrolledText(card,height=20,bg="#0B1220",fg=self.TEXT,insertbackground="white")
        self.txt.pack(fill="both",expand=True,padx=10,pady=(0,10))
        for ev in self.sis.aud.ultimos(): self.txt.insert("end", ev.linea()+"\n")
        self.txt.see("end")
    
    def actualizar_log(self, ev:EventoAuditoria):
        if hasattr(self,"txt"): self.txt.insert("end", ev.linea()+"\n"); self.txt.see("end")

    def _logout(self):
        if messagebox.askyesno("Cerrar sesión", "¿Estás seguro de que querés cerrar sesión?"):
            self.sis.auth.logout(self.token, self.usr.usuario())
            
            # CRÍTICO: Remover observador antes de destruir ventana
            try:
                if self in self.sis.aud._obs:
                    self.sis.aud._obs.remove(self)
            except:
                pass
            
            self.root.destroy()
            AppLogin(self.sis).run()

    def run(self): self.root.mainloop()

# ------------------ MAIN ------------------

def main():
    sis = SistemaRBAC()
    
    # Función que se ejecuta después del splash
    def show_login():
        AppLogin(sis).run()
    
    # Mostrar splash screen primero
    splash = SplashScreen(show_login)
    splash.run()

if __name__ == "__main__":
    main()