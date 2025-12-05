# Etapa 1: Construcción de la imagen con las dependencias
FROM php:8.2-apache AS build

# Actualizar paquetes e instalar dependencias necesarias
RUN apt-get update && apt-get install -y \
    git \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libpq-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd pdo_pgsql

# Instalar Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Copiar archivos de Composer
COPY composer.json composer.lock ./

# Instalar dependencias PHP con Composer
RUN composer install --no-dev --optimize-autoloader --no-interaction --no-progress

# Copiar el código fuente al contenedor
COPY . /var/www/html/

# Eliminar el archivo predeterminado de Apache
RUN rm -f /var/www/html/index.html

# Etapa 2: Configuración de Apache y ejecución
FROM php:8.2-apache

# Actualizar paquetes e instalar dependencias necesarias
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libpq-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd pdo_pgsql

# Configurar Apache para escuchar en el puerto 8000
RUN sed -i 's/Listen 80/Listen 8000/' /etc/apache2/ports.conf

# Copiar el código fuente desde la etapa de construcción
COPY --from=build /var/www/html /var/www/html

# Activar el módulo rewrite de Apache
RUN a2enmod rewrite

# Configurar el ServerName para evitar advertencias
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# Exponer el puerto 8000
EXPOSE 8000

# Comando para iniciar Apache
CMD ["apache2-foreground"]