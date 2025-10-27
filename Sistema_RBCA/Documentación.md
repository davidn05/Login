# Sistema de Gestión de Usuarios con Roles y Accesos (RBAC)

Versión: 2.4  
Archivo principal: `sistema_login_2.4.py`

---

## 1. Descripción general

El sistema implementa control de acceso basado en roles (RBAC) para gestionar usuarios, roles y accesos (permisos).  
Incluye autenticación, autorización, gestión administrativa y auditoría visual en una interfaz de escritorio construida con Tkinter.

---

## 2. Objetivos

- Autenticar usuarios de forma segura.
- Autorizar acciones mediante roles y accesos.
- Permitir a la administradora crear y administrar usuarios sin modificar código.
- Registrar y mostrar auditoría en tiempo real.
- Mantener una arquitectura clara aplicando POO, SOLID y patrones de diseño.

---

## 3. Roles predefinidos y accesos

| Rol                       | Accesos principales                                  |
|--------------------------|-------------------------------------------------------|
| Personal                 | Ver documentos                                       |
| Jefe de Área             | Ver y editar documentos                              |
| Gerente                  | Ver documentos, Generar reportes                     |
| Director                 | Ver documentos, Generar reportes                     |
| Supervisor               | Ver documentos, Eliminar documentos                  |
| Administrador del Sistema| Todos los accesos                                    |

---

## 4. Usuarios iniciales

> Contraseña inicial para todos: `1230`

| Usuario         | Rol                       |
|-----------------|---------------------------|
| sofia.ramirez   | Administrador del Sistema |
| carlos.mendez   | Personal                  |
| martin.lopez    | Gerente                   |
| laura.garcia    | Director                  |
| diego.fernandez | Supervisor                |
| ana.torres      | Jefe de Área              |

---

## 5. Interfaz

- Panel izquierdo: datos del usuario (nombre, usuario, email, roles, accesos) y botón de cerrar sesión.
- Panel derecho: pestañas
  - **Accesos**: lista los accesos visibles del usuario (solo lectura).
  - **Gestionar usuarios**: visible solo para la administradora; alta de usuarios, asignación de rol y otorgamiento/revocación de accesos.
  - **Auditoría**: visible para usuarios con el acceso `auditoria.ver`; muestra eventos en tiempo real.

---

## 6. Flujos principales

### 6.1 Inicio de sesión
1. Ingresar usuario y contraseña.
2. Si son válidos, acceso al panel principal.
3. Si son inválidos, mostrar: “Usuario o contraseña incorrectos”.

### 6.2 Gestión de usuarios (administradora)
1. Abrir pestaña **Gestionar usuarios**.
2. Completar usuario, nombre, email, contraseña y rol.
3. (Opcional) Marcar accesos directos.
4. Crear usuario.
5. En la tabla: otorgar o quitar accesos a usuarios existentes.
6. Ver los eventos en la pestaña **Auditoría**.

### 6.3 Auditoría
- Registra logins, creación de usuarios y cambios de accesos.

---

## 7. Seguridad

- Contraseñas: 1230

---

## 8. Arquitectura

- Dominio: `Usuario`, `Rol`, `Acceso`, `EventoAuditoria`.
- Aplicación/Servicios: `ServicioAutenticacion`, `ServicioAutorizacion`, `ServicioGestion`, `ServicioAuditoria`.
- Infraestructura: `RepoUsuarios`, `RepoRoles`, `RepoAccesos`, `HashService`, `TokenService`.
- Presentación: `AppLogin`, `AppMain` (Tkinter).
- Fachada/Singleton: `SistemaRBAC`.

## 8.1 Principios SOLID aplicados
| Principio                         | Aplicación                                                                                                                    |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **S - Responsabilidad Única**     | Cada clase tiene una función específica: `Usuario` gestiona datos, `Rol` define permisos y `SistemaLogin` controla el acceso. |
| **O - Abierto/Cerrado**           | Se pueden agregar nuevos roles sin modificar el código existente, solo extendiendo `FabricaRoles`.                            |
| **L - Sustitución de Liskov**     | Las subclases de `Usuario` pueden sustituir la clase base sin alterar el funcionamiento.                                      |
| **I - Segregación de Interfaces** | Cada clase define solo los métodos que necesita, sin imponer interfaces innecesarias.                                         |
| **D - Inversión de Dependencias** | `SistemaLogin` depende de abstracciones (`Usuario`, `Rol`) en lugar de implementaciones concretas.                            |

## 8.2 Patrones de diseño usados
### Factory Method
Permite crear usuarios o roles según su tipo sin modificar la lógica base

### Strategy

Permite definir políticas de autorización distintas para cada tipo de rol, encapsulando la lógica en estrategias independientes.

### Singleton

El sistema utiliza este patrón en SistemaLogin para asegurar que exista una única instancia durante toda la ejecución.

---

## 9. Criterios de aceptación

- La administradora puede crear usuarios con rol y accesos.
- Auditoría visible para quienes posean el acceso.
- Usuarios sin permisos no ven pestañas restringidas.
- Mensaje claro en login ante error.

---

## 10. Ejecución

1. Requisitos: Python 3.10 o superior.
2. Guardar `sistema_login_2.4.py`.
3. Ejecutar:
   ```bash
   python sistema_login_2.4.py
