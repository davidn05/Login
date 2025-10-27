Aplicación de Conceptos POO

Encapsulación
Los atributos nombreUsuario, clave y rol son privados, y se accede a ellos mediante métodos públicos (getRol, validarClave), protegiendo los datos sensibles.

Abstracción
Las clases Usuario, Rol y SistemaLogin representan entidades reales de forma simplificada.
No importa cómo se almacenan los datos internamente, sino qué hacen.

Herencia
Podrían crearse subclases específicas por tipo de usuario:
Administrador hereda de Usuario
Gerente hereda de Usuario
Cada una redefine comportamientos o permisos.

Polimorfismo
El método autorizar() se comporta distinto según el rol:
si usuario.getRol().nombre == "Administrador del Sistema"
imprimir("Acceso completo.")
sino si usuario.getRol().nombre == "Gerente"
imprimir("Acceso a informes y aprobaciones.")

Principios SOLID Aplicados

S - Responsabilidad Única: Cada clase cumple una función específica (Usuario gestiona datos, Rol define permisos, SistemaLogin controla el acceso).
O - Abierto/Cerrado: Se pueden agregar nuevos roles sin modificar el código base.
L - Sustitución de Liskov: Las subclases de Usuario pueden sustituir la clase base sin alterar el funcionamiento.
I - Segregación de Interfaces: No se imponen métodos innecesarios; cada clase tiene su propia interfaz lógica.
D - Inversión de Dependencias: SistemaLogin depende de abstracciones (Usuario, Rol), no de implementaciones concretas.

Patrones de Diseño Posibles

Factory Method
Permite crear usuarios o roles según tipo:
Clase FabricaUsuarios
método crearUsuario(tipo, nombre, clave)
si tipo == "Administrador" → retornar nuevo Admin(nombre, clave)

Strategy
Define políticas de autorización distintas según el rol, encapsulando la lógica de permisos en estrategias separadas.

Singleton
Asegura que solo exista una instancia de SistemaLogin en todo el sistema.

Ejemplo Conceptual
Usuario: carlos
Contraseña: ******
El sistema verifica en la base de datos
Credenciales válidas
Rol: Gerente
Acceso permitido a panel de gestión

Fundamento Teórico

¿Qué es un Login?
El login o inicio de sesión es el proceso mediante el cual un usuario accede a un sistema informático verificando su identidad.
Implica dos elementos:
Identificador: quién dice ser (usuario o email).
Credencial: prueba de identidad (contraseña, token, biometría, etc.).

Etapas del Proceso
Entrada de datos: el usuario ingresa nombre y clave.
Validación: comparación con la base de datos.
Autenticación: confirmación de identidad.
Autorización: habilitación de funciones según el rol.
Sesión activa: el sistema mantiene el acceso hasta cierre o expiración.

Relación con la POO
La POO permite representar el sistema de login mediante clases que colaboran entre sí:
Usuario: contiene datos y credenciales.
Rol: define los permisos.
SistemaLogin: gestiona la autenticación y autorización.
Esto garantiza seguridad, control de acceso y trazabilidad, además de un diseño extensible y fácil de mantener.

Metodología
Tipo de trabajo: Grupal
Grupo: NRG Software 
Profesor: Mgtr. Arzamendia, Carlos Marcelo y Lic. Del Rosario, Gabriel Dario

Licencia
Este proyecto es de uso académico con fines educativos.
© 2025 — Universidad de la Cuenca del Plata.
