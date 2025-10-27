import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from typing import List, Optional

# ==================== MODELO / DOMINIO ====================

class Rol:
    """
    Clase que representa un rol dentro del sistema.
    Encapsula el nombre del rol y sus permisos asociados.
    
    Principio SOLID: Single responsability - solo gestiona roles y permisos.
    """
    def __init__(self, nombre: str, permisos: List[str]):
        """
        Constructor de la clase Rol.
        
        Args:
            nombre: Nombre del rol (ej: "Gerente")
            permisos: Lista de permisos asociados al rol
        """
        # Atributos públicos (no hay encapsulación estricta en esta clase)
        self.nombre = nombre
        self.permisos = permisos
    
    def tiene_permiso(self, accion: str) -> bool:
        """
        Verifica si el rol tiene un permiso específico.
        
        Args:
            accion: Permiso a verificar
            
        Returns:
            True si el rol tiene el permiso, False en caso contrario
        """
        return accion in self.permisos
    
    def obtener_permisos(self) -> str:
        """Retorna los permisos como string formateado."""
        return ", ".join(self.permisos)


class Usuario:
    """
    Clase que representa un usuario del sistema.
    Aplica ENCAPSULACIÓN: los atributos son privados y solo accesibles mediante métodos.
    
    Principio SOLID: Responsabilidad Única - solo gestiona datos de usuario.
    
    --- CONCEPTOS POO APLICADOS ---
    ✓ ENCAPSULACIÓN: Los atributos __nombre_usuario, __clave y __rol son privados
      (doble guion bajo). Solo se accede mediante métodos públicos (get_nombre_usuario,
      get_rol, validar_clave), protegiendo la integridad de los datos.
    ✓ ABSTRACCIÓN: Simplifica la complejidad de un usuario real en atributos 
      esenciales y operaciones básicas.
    ✓ HERENCIA (potencial): Esta clase puede ser heredada para crear usuarios
      especializados (ej: UsuarioTemporal, UsuarioExterno).
    """
    def __init__(self, nombre_usuario: str, clave: str, rol: Rol):
        """
        Constructor de la clase Usuario.
        
        Args:
            nombre_usuario: Nombre de usuario para login
            clave: Contraseña del usuario
            rol: Objeto Rol asignado al usuario
        """
        # ENCAPSULACIÓN: Atributos privados (prefijo __)
        self.__nombre_usuario = nombre_usuario  # Atributo privado
        self.__clave = clave                    # Atributo privado
        self.__rol = rol                        # Atributo privado
    
    def get_nombre_usuario(self) -> str:
        """
        Obtiene el nombre de usuario. Método público de acceso.
        
        ENCAPSULACIÓN: Método getter que permite acceso controlado al atributo privado.
        """
        return self.__nombre_usuario
    
    def get_rol(self) -> Rol:
        """
        Obtiene el rol del usuario. Método público de acceso.
        
        ENCAPSULACIÓN: Método getter que permite acceso controlado al atributo privado.
        """
        return self.__rol
    
    def validar_clave(self, entrada_clave: str) -> bool:
        """
        Valida si la clave ingresada coincide con la almacenada.
        
        Args:
            entrada_clave: Clave ingresada por el usuario
            
        Returns:
            True si la clave es correcta, False en caso contrario
            
        ENCAPSULACIÓN: Protege el acceso directo a la clave, solo permite validación.
        """
        return self.__clave == entrada_clave


class SistemaLogin:
    """
    Clase que gestiona el sistema de autenticación y autorización.
    Implementa patrón SINGLETON para garantizar una única instancia.
    
    Principios SOLID:
    - Responsabilidad Única: solo gestiona autenticación/autorización
    - Abierto/Cerrado: se pueden agregar nuevos roles sin modificar esta clase
    - Inversión de Dependencias: depende de abstracciones (Rol, Usuario)
    
    --- CONCEPTOS POO APLICADOS ---
    ✓ ENCAPSULACIÓN: El atributo __lista_usuarios es privado, solo accesible
      mediante métodos públicos (registrar_usuario, autenticar).
    ✓ ABSTRACCIÓN: Oculta la complejidad interna del proceso de autenticación
      y autorización, exponiendo solo interfaces simples.
    ✓ POLIMORFISMO: El método autorizar() genera diferentes respuestas según
      el tipo de rol del usuario (comportamiento polimórfico).
    """
    __instancia = None  # Variable de clase para Singleton
    
    def __new__(cls):
        """
        Implementación del patrón Singleton.
        Garantiza que solo exista una instancia de SistemaLogin.
        """
        if cls.__instancia is None:
            cls.__instancia = super().__new__(cls)
            cls.__instancia.__inicializado = False
        return cls.__instancia
    
    def __init__(self):
        """
        Constructor que se ejecuta solo una vez (Singleton).
        
        ENCAPSULACIÓN: Inicializa atributos privados de forma controlada.
        """
        if not self.__inicializado:
            self.__lista_usuarios: List[Usuario] = []  # Atributo privado
            self.__inicializado = True
    
    def registrar_usuario(self, usuario: Usuario) -> None:
        """
        Registra un nuevo usuario en el sistema.
        
        Args:
            usuario: Objeto Usuario a registrar
        """
        self.__lista_usuarios.append(usuario)
    
    def autenticar(self, nombre: str, clave: str) -> Optional[Usuario]:
        """
        Autentica un usuario verificando sus credenciales.
        
        Args:
            nombre: Nombre de usuario
            clave: Contraseña ingresada
            
        Returns:
            Objeto Usuario si las credenciales son correctas, None en caso contrario
        """
        for usuario in self.__lista_usuarios:
            if usuario.get_nombre_usuario() == nombre and usuario.validar_clave(clave):
                return usuario
        return None
    
    def autorizar(self, usuario: Usuario) -> str:
        """
        Autoriza el acceso del usuario y retorna información sobre sus permisos.
        
        Args:
            usuario: Usuario autenticado
            
        Returns:
            Mensaje con información de acceso y permisos
            
        --- POLIMORFISMO ---
        Este método demuestra polimorfismo: diferentes roles generan diferentes
        respuestas y comportamientos. Aunque todos los usuarios pasan por el mismo
        método, el resultado varía según su rol (nivel de acceso diferente).
        """
        rol = usuario.get_rol()
        mensaje = f"✓ Bienvenido/a {usuario.get_nombre_usuario()}!\n\n"
        mensaje += f"Rol asignado: {rol.nombre}\n"
        # POLIMORFISMO: obtener_nivel_acceso retorna diferente según el rol
        mensaje += f"Nivel de acceso: {self.__obtener_nivel_acceso(rol)}\n\n"
        mensaje += f"Permisos autorizados:\n"
        
        for permiso in rol.permisos:
            mensaje += f"  • {permiso}\n"
        
        return mensaje
    
    def __obtener_nivel_acceso(self, rol: Rol) -> str:
        """
        Determina el nivel de acceso según el rol.
        
        Args:
            rol: Rol del usuario
            
        Returns:
            Descripción del nivel de acceso
            
        --- ENCAPSULACIÓN ---
        Método privado (prefijo __) que oculta la lógica interna de determinación
        de niveles de acceso. Solo accesible desde dentro de la clase.
        
        --- POLIMORFISMO ---
        Retorna diferentes valores según el tipo de rol, demostrando comportamiento
        polimórfico basado en el contexto del objeto.
        """
        niveles = {
            "Administrador del Sistema": "TOTAL - Control completo del sistema",
            "Director": "ALTO - Decisiones estratégicas",
            "Gerente": "MEDIO-ALTO - Gestión y aprobaciones",
            "Jefe de Área": "MEDIO - Edición de contenidos",
            "Supervisor": "MEDIO - Supervisión y control",
            "Personal": "BÁSICO - Solo lectura"
        }
        return niveles.get(rol.nombre, "Definido por permisos específicos")
    
    def obtener_cantidad_usuarios(self) -> int:
        """Retorna la cantidad de usuarios registrados."""
        return len(self.__lista_usuarios)


# ==================== FÁBRICA DE ROLES (Factory Pattern) ====================

class FabricaRoles:
    """
    Implementa el patrón Factory Method para crear roles predefinidos.
    
    Principio SOLID: Abierto/Cerrado - se pueden agregar nuevos roles
    sin modificar el código existente.
    
    --- CONCEPTOS POO APLICADOS ---
    ✓ ABSTRACCIÓN: Oculta la complejidad de la creación de roles, ofreciendo
      métodos simples para obtener roles predefinidos.
    ✓ HERENCIA (potencial): Esta clase podría ser heredada para crear fábricas
      especializadas (ej: FabricaRolesTemporales, FabricaRolesExternos).
    """
    
    @staticmethod
    def crear_rol_personal() -> Rol:
        """Crea y retorna un rol de Personal."""
        return Rol("Personal", ["LECTURA"])
    
    @staticmethod
    def crear_rol_jefe_area() -> Rol:
        """Crea y retorna un rol de Jefe de Área."""
        return Rol("Jefe de Área", ["LECTURA", "EDICIÓN"])
    
    @staticmethod
    def crear_rol_gerente() -> Rol:
        """Crea y retorna un rol de Gerente."""
        return Rol("Gerente", ["LECTURA", "EDICIÓN", "APROBACIÓN"])
    
    @staticmethod
    def crear_rol_director() -> Rol:
        """Crea y retorna un rol de Director."""
        return Rol("Director", ["LECTURA", "EDICIÓN", "APROBACIÓN", "DECISIÓN"])
    
    @staticmethod
    def crear_rol_supervisor() -> Rol:
        """Crea y retorna un rol de Supervisor."""
        return Rol("Supervisor", ["LECTURA", "CONTROL"])
    
    @staticmethod
    def crear_rol_administrador() -> Rol:
        """Crea y retorna un rol de Administrador del Sistema."""
        return Rol("Administrador del Sistema", ["GESTIÓN_TOTAL"])


# ==================== CONTROLADOR ====================

class ControladorLogin:
    """
    Controlador que maneja la lógica de la interfaz gráfica.
    Separa la lógica de negocio (modelo) de la presentación (vista).
    
    --- CONCEPTOS POO APLICADOS ---
    ✓ ENCAPSULACIÓN: Encapsula la lógica de procesamiento de login,
      protegiendo el sistema de accesos directos desde la vista.
    ✓ ABSTRACCIÓN: Simplifica la interacción entre vista y modelo,
      actuando como intermediario.
    """
    
    def __init__(self, sistema: SistemaLogin):
        """
        Constructor del controlador.
        
        Args:
            sistema: Instancia del SistemaLogin
        """
        self.sistema = sistema
    
    def procesar_login(self, nombre: str, clave: str) -> tuple[bool, str]:
        """
        Procesa el intento de login.
        
        Args:
            nombre: Nombre de usuario ingresado
            clave: Contraseña ingresada
            
        Returns:
            Tupla (éxito, mensaje) donde éxito es bool y mensaje es str
        """
        # Validaciones básicas
        if not nombre or not clave:
            return False, "Por favor, completá todos los campos."
        
        # Autenticar usuario
        usuario_autenticado = self.sistema.autenticar(nombre, clave)
        
        if usuario_autenticado:
            # Autorizar y obtener mensaje de permisos
            mensaje = self.sistema.autorizar(usuario_autenticado)
            return True, mensaje
        else:
            return False, "Acceso denegado.\nCredenciales incorrectas."


# ==================== VISTA / INTERFAZ GRÁFICA ====================

class VistaLogin:
    """
    Clase que gestiona la interfaz gráfica del sistema de login.
    Aplica el patrón MVC (Modelo-Vista-Controlador).
    """
    
    # Paleta de colores profesional
    COLOR_FONDO = "#F0F4F8"
    COLOR_TARJETA = "#FFFFFF"
    COLOR_PRIMARIO = "#2563EB"
    COLOR_PRIMARIO_HOVER = "#1D4ED8"
    COLOR_TEXTO = "#1F2937"
    COLOR_TEXTO_SECUNDARIO = "#6B7280"
    COLOR_ERROR = "#DC2626"
    COLOR_EXITO = "#059669"
    
    def __init__(self, controlador: ControladorLogin):
        """
        Constructor de la vista.
        
        Args:
            controlador: Instancia del ControladorLogin
        """
        self.controlador = controlador
        self.root = tk.Tk()
        self.configurar_ventana()
        self.crear_interfaz()
    
    def configurar_ventana(self):
        """Configura la ventana principal."""
        self.root.title("Sistema de Login - Control de Acceso por Rol")
        self.root.configure(bg=self.COLOR_FONDO)
        self.root.resizable(False, False)
        
        # Dimensiones de la ventana
        ancho_ventana = 500
        alto_ventana = 550
        
        # Centrar ventana en pantalla
        ancho_pantalla = self.root.winfo_screenwidth()
        alto_pantalla = self.root.winfo_screenheight()
        pos_x = (ancho_pantalla - ancho_ventana) // 2
        pos_y = (alto_pantalla - alto_ventana) // 2
        
        self.root.geometry(f"{ancho_ventana}x{alto_ventana}+{pos_x}+{pos_y}")
    
    def crear_interfaz(self):
        """Crea todos los elementos de la interfaz gráfica."""
        # Frame principal con padding
        frame_principal = tk.Frame(self.root, bg=self.COLOR_FONDO)
        frame_principal.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Tarjeta de login
        self.tarjeta = tk.Frame(
            frame_principal,
            bg=self.COLOR_TARJETA,
            relief="flat",
            bd=0
        )
        self.tarjeta.pack(fill="both", expand=True)
        
        # Agregar sombra simulada con bordes
        self.tarjeta.configure(highlightbackground="#E5E7EB", highlightthickness=1)
        
        # Contenido de la tarjeta
        self.crear_encabezado()
        self.crear_formulario()
        self.crear_boton_login()
        self.crear_pie()
    
    def crear_encabezado(self):
        """Crea el encabezado de la tarjeta."""
        frame_header = tk.Frame(self.tarjeta, bg=self.COLOR_TARJETA)
        frame_header.pack(fill="x", padx=30, pady=(30, 10))
        
        # Ícono decorativo
        label_icono = tk.Label(
            frame_header,
            text="🔐",
            font=("Segoe UI", 32),
            bg=self.COLOR_TARJETA
        )
        label_icono.pack()
        
        # Título
        label_titulo = tk.Label(
            frame_header,
            text="Iniciar Sesión",
            font=("Segoe UI", 24, "bold"),
            fg=self.COLOR_TEXTO,
            bg=self.COLOR_TARJETA
        )
        label_titulo.pack(pady=(10, 5))
        
        # Subtítulo
        label_subtitulo = tk.Label(
            frame_header,
            text="Acceso seguro con control de roles y permisos",
            font=("Segoe UI", 10),
            fg=self.COLOR_TEXTO_SECUNDARIO,
            bg=self.COLOR_TARJETA
        )
        label_subtitulo.pack()
    
    def crear_formulario(self):
        """Crea el formulario de login."""
        frame_form = tk.Frame(self.tarjeta, bg=self.COLOR_TARJETA)
        frame_form.pack(fill="x", padx=30, pady=20)
        
        # Campo Usuario
        label_usuario = tk.Label(
            frame_form,
            text="Nombre de Usuario",
            font=("Segoe UI", 11, "bold"),
            fg=self.COLOR_TEXTO,
            bg=self.COLOR_TARJETA,
            anchor="w"
        )
        label_usuario.pack(fill="x", pady=(10, 5))
        
        self.entry_usuario = tk.Entry(
            frame_form,
            font=("Segoe UI", 12),
            relief="solid",
            bd=1,
            highlightthickness=2,
            highlightcolor=self.COLOR_PRIMARIO,
            highlightbackground="#D1D5DB"
        )
        self.entry_usuario.pack(fill="x", ipady=8)
        
        # Campo Contraseña
        label_clave = tk.Label(
            frame_form,
            text="Contraseña",
            font=("Segoe UI", 11, "bold"),
            fg=self.COLOR_TEXTO,
            bg=self.COLOR_TARJETA,
            anchor="w"
        )
        label_clave.pack(fill="x", pady=(20, 5))
        
        # Frame para contraseña y botón mostrar/ocultar
        frame_password = tk.Frame(frame_form, bg=self.COLOR_TARJETA)
        frame_password.pack(fill="x")
        
        self.entry_clave = tk.Entry(
            frame_password,
            font=("Segoe UI", 12),
            show="●",
            relief="solid",
            bd=1,
            highlightthickness=2,
            highlightcolor=self.COLOR_PRIMARIO,
            highlightbackground="#D1D5DB"
        )
        self.entry_clave.pack(side="left", fill="x", expand=True, ipady=8)
        
        # Checkbox mostrar contraseña
        self.var_mostrar_clave = tk.BooleanVar()
        check_mostrar = tk.Checkbutton(
            frame_form,
            text="Mostrar contraseña",
            variable=self.var_mostrar_clave,
            command=self.toggle_password,
            font=("Segoe UI", 9),
            fg=self.COLOR_TEXTO_SECUNDARIO,
            bg=self.COLOR_TARJETA,
            activebackground=self.COLOR_TARJETA,
            selectcolor=self.COLOR_TARJETA,
            relief="flat"
        )
        check_mostrar.pack(anchor="w", pady=(5, 0))
        
        # Label para mensajes de feedback
        self.label_feedback = tk.Label(
            frame_form,
            text="",
            font=("Segoe UI", 9),
            fg=self.COLOR_ERROR,
            bg=self.COLOR_TARJETA,
            wraplength=400,
            justify="left"
        )
        self.label_feedback.pack(fill="x", pady=(10, 0))
    
    def crear_boton_login(self):
        """Crea el botón de login."""
        frame_boton = tk.Frame(self.tarjeta, bg=self.COLOR_TARJETA)
        frame_boton.pack(fill="x", padx=30, pady=20)
        
        self.boton_login = tk.Button(
            frame_boton,
            text="INICIAR SESIÓN",
            font=("Segoe UI", 12, "bold"),
            fg="white",
            bg=self.COLOR_PRIMARIO,
            activebackground=self.COLOR_PRIMARIO_HOVER,
            activeforeground="white",
            relief="flat",
            cursor="hand2",
            command=self.manejar_login
        )
        self.boton_login.pack(fill="x", ipady=12)
        
        # Efecto hover
        self.boton_login.bind("<Enter>", lambda e: self.boton_login.config(bg=self.COLOR_PRIMARIO_HOVER))
        self.boton_login.bind("<Leave>", lambda e: self.boton_login.config(bg=self.COLOR_PRIMARIO))
    
    def crear_pie(self):
        """Crea el pie de página con información adicional."""
        frame_pie = tk.Frame(self.tarjeta, bg=self.COLOR_TARJETA)
        frame_pie.pack(fill="x", padx=30, pady=(0, 20))
        
        # Separador
        separador = tk.Frame(frame_pie, bg="#E5E7EB", height=1)
        separador.pack(fill="x", pady=10)
        
        # Información de usuarios de prueba
        label_info = tk.Label(
            frame_pie,
            text="Usuarios de prueba (contraseña: 1230):\ncarlos.mendez, sofia.ramirez, martin.lopez, laura.garcia, diego.fernandez, ana.torres",
            font=("Segoe UI", 8),
            fg=self.COLOR_TEXTO_SECUNDARIO,
            bg=self.COLOR_TARJETA,
            justify="center"
        )
        label_info.pack()
    
    def toggle_password(self):
        """Alterna entre mostrar y ocultar la contraseña."""
        if self.var_mostrar_clave.get():
            self.entry_clave.config(show="")
        else:
            self.entry_clave.config(show="●")
    
    def manejar_login(self):
        """Maneja el evento de click en el botón de login."""
        nombre = self.entry_usuario.get().strip()
        clave = self.entry_clave.get()
        
        # Procesar login mediante el controlador
        exito, mensaje = self.controlador.procesar_login(nombre, clave)
        
        if exito:
            # Login exitoso
            self.label_feedback.config(text="✓ Acceso autorizado", fg=self.COLOR_EXITO)
            messagebox.showinfo("Acceso Autorizado", mensaje)
            
            # Limpiar campos
            self.entry_usuario.delete(0, tk.END)
            self.entry_clave.delete(0, tk.END)
            self.entry_usuario.focus()
            self.label_feedback.config(text="")
        else:
            # Login fallido
            self.label_feedback.config(text="✗ " + mensaje, fg=self.COLOR_ERROR)
            self.entry_clave.delete(0, tk.END)
            self.entry_clave.focus()
    
    def ejecutar(self):
        """Inicia el loop principal de la interfaz gráfica."""
        # Atajo de teclado: Enter para login
        self.root.bind("<Return>", lambda e: self.manejar_login())
        
        # Establecer foco inicial
        self.entry_usuario.focus()
        
        # Iniciar loop
        self.root.mainloop()


# ==================== INICIALIZACIÓN DEL PROGRAMA ====================

def inicializar_sistema() -> SistemaLogin:
    """
    Inicializa el sistema creando roles y usuarios de prueba.
    
    Returns:
        Instancia configurada de SistemaLogin
    """
    # Crear instancia del sistema (Singleton)
    sistema = SistemaLogin()
    
    # Crear roles usando la fábrica (Factory Pattern)
    fabrica = FabricaRoles()
    rol_personal = fabrica.crear_rol_personal()
    rol_jefe = fabrica.crear_rol_jefe_area()
    rol_gerente = fabrica.crear_rol_gerente()
    rol_director = fabrica.crear_rol_director()
    rol_supervisor = fabrica.crear_rol_supervisor()
    rol_admin = fabrica.crear_rol_administrador()
    
    # Registrar usuarios de prueba
    sistema.registrar_usuario(Usuario("carlos.mendez", "1230", rol_personal))
    sistema.registrar_usuario(Usuario("sofia.ramirez", "1230", rol_admin))
    sistema.registrar_usuario(Usuario("martin.lopez", "1230", rol_gerente))
    sistema.registrar_usuario(Usuario("laura.garcia", "1230", rol_director))
    sistema.registrar_usuario(Usuario("diego.fernandez", "1230", rol_supervisor))
    sistema.registrar_usuario(Usuario("ana.torres", "1230", rol_jefe))
    
    return sistema


#====Clase main====
def main():
    # Inicializar el sistema (Modelo)
    sistema = inicializar_sistema()
    
    # Crear el controlador
    controlador = ControladorLogin(sistema)
    
    # Crear la vista
    vista = VistaLogin(controlador)
    
    # Ejecutar la aplicación
    vista.ejecutar()


# Punto de entrada del programa
if __name__ == "__main__":
    main()