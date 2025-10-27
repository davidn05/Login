# Sistema de Login con Control de Acceso por Rol

Versión: 1.0  
Archivo principal: `sistema_login_1.py`

---

## 1. Descripción

El sistema implementa un **login básico con control de acceso por rol**, diseñado bajo principios de **Programación Orientada a Objetos (POO)**.  
Permite autenticar usuarios mediante nombre y contraseña, identificar su rol y mostrar los permisos asociados a ese rol.

El sistema está construido con una **arquitectura MVC (Modelo–Vista–Controlador)** en Python utilizando **Tkinter** para la interfaz gráfica.

---

## 2. Objetivos

- Autenticar usuarios de forma segura y estructurada.  
- Mostrar permisos y nivel de acceso según el rol asignado.  
- Aplicar los principios fundamentales de la **POO** y los **principios SOLID**.  
- Presentar una estructura modular, extensible y fácil de mantener.

---

## 3. Estructura del sistema

El sistema se organiza en tres capas principales:

| Capa | Componente | Descripción |
|------|-------------|-------------|
| **Modelo / Dominio** | `Usuario`, `Rol`, `SistemaLogin`, `FabricaRoles` | Representa los datos y la lógica del negocio. |
| **Controlador** | `ControladorLogin` | Gestiona la comunicación entre la vista y el modelo, procesando los intentos de login. |
| **Vista / Interfaz** | `VistaLogin` | Interfaz de usuario (Tkinter) encargada de la interacción con el sistema. |

---

## 4. Aplicación de conceptos POO

### Encapsulación
Los atributos `nombreUsuario`, `clave` y `rol` son **privados**.  
Se accede a ellos mediante métodos públicos como `getRol` y `validarClave`, lo que protege los datos sensibles del usuario y evita su manipulación directa.

### Abstracción
Las clases `Usuario`, `Rol` y `SistemaLogin` representan **entidades reales** de manera simplificada.  
No interesa cómo se almacenan internamente los datos, sino las acciones que pueden realizar (por ejemplo, validar o autorizar).

### Herencia
Podrían crearse subclases específicas para distintos tipos de usuario:
- `Administrador` hereda de `Usuario`
- `Gerente` hereda de `Usuario`

Cada subclase puede redefinir comportamientos o permisos particulares.

### Polimorfismo
El método `autorizar()` se comporta de manera diferente según el rol del usuario

## 5. Principios SOLID aplicados
| Principio                         | Aplicación                                                                                                                    |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **S - Responsabilidad Única**     | Cada clase tiene una función específica: `Usuario` gestiona datos, `Rol` define permisos y `SistemaLogin` controla el acceso. |
| **O - Abierto/Cerrado**           | Se pueden agregar nuevos roles sin modificar el código existente, solo extendiendo `FabricaRoles`.                            |
| **L - Sustitución de Liskov**     | Las subclases de `Usuario` pueden sustituir la clase base sin alterar el funcionamiento.                                      |
| **I - Segregación de Interfaces** | Cada clase define solo los métodos que necesita, sin imponer interfaces innecesarias.                                         |
| **D - Inversión de Dependencias** | `SistemaLogin` depende de abstracciones (`Usuario`, `Rol`) en lugar de implementaciones concretas.                            |

## 6. Patrones de diseño usados
### Factory Method
Permite crear usuarios o roles según su tipo sin modificar la lógica base

### Strategy

Permite definir políticas de autorización distintas para cada tipo de rol, encapsulando la lógica en estrategias independientes.

### Singleton

El sistema utiliza este patrón en SistemaLogin para asegurar que exista una única instancia durante toda la ejecución.

## 8. Fundamento teórico
### ¿Qué es un Login?

El login o inicio de sesión es el proceso mediante el cual un usuario accede a un sistema informático verificando su identidad.
Implica dos componentes principales:

Identificador: quién dice ser (usuario, correo, ID).

Credencial: prueba de identidad (contraseña, token, biometría, etc.).

### Etapas del proceso

Entrada de datos: el usuario ingresa su nombre y contraseña.

Validación: se comparan las credenciales con los registros del sistema.

Autenticación: el sistema confirma la identidad del usuario.

Autorización: se otorgan los permisos correspondientes según el rol.

Sesión activa: el sistema mantiene el acceso hasta que se cierra la sesión.

### Relación con la POO

La Programación Orientada a Objetos permite estructurar el sistema de login en clases interconectadas:

Usuario: almacena datos y credenciales.

Rol: define los permisos del usuario.

SistemaLogin: administra la autenticación y autorización.

Este enfoque ofrece seguridad, trazabilidad y facilidad de mantenimiento, además de la posibilidad de extender el sistema sin romper su estructura.

## 9. Ejecución del sistema

Requisitos: Python 3.10 o superior.

Guardar el archivo sistema_login_1.py.

Iniciar sesión con alguno de los usuarios de prueba (contraseña: 1230):
carlos.mendez
sofia.ramirez
martin.lopez
laura.garcia
diego.fernandez
ana.torres

## 10. Arquitectura del sistema

Dominio: Rol, Usuario, SistemaLogin, FabricaRoles.

Controlador: ControladorLogin.

Vista: VistaLogin (interfaz de Tkinter).

El diseño sigue un enfoque MVC (Modelo–Vista–Controlador), lo que separa responsabilidades y mejora la mantenibilidad del código.
