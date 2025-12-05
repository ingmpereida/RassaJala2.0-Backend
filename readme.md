# API REST RASSA JALA con Flight PHP

API RESTful desarrollada con el framework Flight de PHP, un micro-framework ligero y eficiente para la creación de servicios web.

## 📋 Requisitos Previos

Antes de comenzar, asegúrate de tener instalado:

- PHP 7.4 o superior
- Composer (gestor de dependencias de PHP)
- Git

## 🚀 Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/tu-repositorio.git
cd tu-repositorio
```

### 2. Instalar dependencias

Ejecuta el siguiente comando para instalar todas las dependencias del proyecto mediante Composer:

```bash
composer install
```

Este comando leerá el archivo `composer.json` e instalará el framework Flight y todas las librerías necesarias en la carpeta `vendor/`.

## 🏃‍♂️ Ejecución del Servidor

### Modo Local (solo en tu computadora)

Para iniciar el servidor de desarrollo de PHP, ejecuta:

```bash
php -S localhost:8000
```

Luego accede a la siguiente URL en tu navegador:

```
http://localhost:8000/api/v1
```

Si todo funciona correctamente, deberías ver un mensaje de "Hola mundo" o una respuesta JSON similar.

### Modo Red Local (para conectar con frontend u otros dispositivos)

Cuando necesites que otros dispositivos en tu red local (como un frontend en otro equipo o tu móvil) accedan a la API, debes usar la dirección IP de tu computadora en lugar de `localhost`.

**Pasos:**

1. Obtén la dirección IP de tu computadora:
   - **Windows**: Abre CMD y ejecuta `ipconfig`
   - **Linux/Mac**: Abre la terminal y ejecuta `ifconfig` o `ip addr`

2. Inicia el servidor con tu IP:

```bash
php -S 192.168.0.106:8000
```

> **Nota:** Reemplaza `192.168.0.106` con la IP real de tu computadora.

3. Accede desde cualquier dispositivo en la misma red:

```
http://192.168.0.106:8000/api/v1
```

## 📁 Estructura del Proyecto

```
BASAILA2.0-BACKEND/
├── classes/              # Clases PHP del proyecto
│   └── Users.php        # Clase de usuarios
├── vendor/              # Dependencias instaladas por Composer
├── .env                 # Variables de entorno (no subir a Git)
├── .env.example         # Ejemplo de variables de entorno
├── .gitignore          # Archivos ignorados por Git
├── .htaccess           # Configuración de Apache
├── composer.json       # Dependencias del proyecto
├── composer.lock       # Versiones exactas de dependencias
├── dockerfile          # Configuración de Docker
└── index.php           # Punto de entrada de la aplicación
```

## 🔧 Configuración

### Variables de Entorno

1. Copia el archivo `.env.example` a `.env`:

```bash
cp .env.example .env
```

2. Edita el archivo `.env` con tus configuraciones locales (base de datos, credenciales, etc.)

## 📝 Endpoints Disponibles

### Verificación de la API

- **GET** `/api/v1`
  - Descripción: Endpoint de prueba que retorna un "Hola mundo"
  - Respuesta: JSON con mensaje de bienvenida

## 🛠️ Tecnologías Utilizadas

- **Flight PHP**: Micro-framework para PHP
- **Composer**: Gestor de dependencias
- **PHP**: Lenguaje de programación del backend

## 📖 Documentación Adicional

Para más información sobre Flight PHP, visita la [documentación oficial](https://flightphp.com/learn).

## 🤝 Contribución

Si deseas contribuir a este proyecto:

1. Haz un Fork del repositorio
2. Crea una rama con tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Agrega nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

