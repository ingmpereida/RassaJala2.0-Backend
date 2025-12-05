<?php
require 'vendor/autoload.php';

if(file_exists(__DIR__.'/../.env')){
    // Solo cargar .env si el archivo existe (para desarrollo local)
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
    $dotenv->load();
}

class Users{

private $db;
function __construct(){
    // Conexión con nuestra BD incluyendo el puerto
    Flight::register('db', PDO::class, ['pgsql:host='.$_ENV['DB_HOST'].';port='.$_ENV['DB_PORT'].';dbname='.$_ENV['DB_NAME'], $_ENV['DB_USER'], $_ENV['DB_PASS']]);

    // Conexión a la BD
    $this->db = Flight::db();
}

    function getAllUsers(){
            // Preparar y ejecutar la consulta
            $query = $this->db->prepare("SELECT 
                usuario.id_usuario, 
                persona.nombre, 
                persona.apellido_paterno, 
                persona.apellido_materno, 
                persona.sexo,
                rol.nombre_rol,
                usuario.activo,
                usuario.nombre_usuario,
                rol.id_rol
                FROM usuario 
                JOIN usuario_rol ON usuario.id_usuario = usuario_rol.fk_id_usuario
                JOIN persona ON persona.id_persona = usuario.fk_id_persona
                JOIN rol ON usuario_rol.fk_id_rol = rol.id_rol
                ORDER BY id_usuario ASC");
            $query->execute();

            // Obtenemos los datos de los usuarios
            $users = $query->fetchAll();

            // Inicializamos el arreglo de respuesta
            $response = [
                "status" => "200 OK",
                "body" => [
                    "data" => []
                ]
            ];

            // Recorremos los resultados de la consulta y los guardamos en el arreglo de datos
            foreach($users as $row){
                $response["body"]["data"][] = [
                    "id_usuario" => $row['id_usuario'],
                    "nombre" => $row['nombre'],
                    "apellido_paterno" => $row['apellido_paterno'],
                    "apellido_materno" => $row['apellido_materno'],
                    "sexo" => $row['sexo'],
                    "activo" => $row['activo'],
                    "nombre_usuario" => $row['nombre_usuario'],
                    "id_rol" => $row['id_rol'],
                    "nombre_rol" => $row['nombre_rol']
                ];
            }

            Flight::json($response, 200); // Enviar como JSON con código 200


    }

    function getCountAllUsers(){
        // Validamos el token de autenticación
        if(!validateToken() == null){

            // Obtener el token sin el prefijo "Bearer" directamente desde los headers
            $headers = apache_request_headers();
            $authorization = $headers["Authorization"] ?? "";
            $token = str_replace("Bearer ", "", $authorization);
    
            // Comprobar si el token está en la lista negra
            $checkQuery = $this->db->prepare("SELECT COUNT(*) FROM lista_negra WHERE token_invalido = :token");
            $checkQuery->execute([":token" => $token]);
            $isBlacklisted = $checkQuery->fetchColumn();
    
            if ($isBlacklisted > 0) {
                // Respuesta en caso de que el token esté en la lista negra
                $response = [
                    "status" => "401 Unauthorized",
                    "body" => ["data" => [
                        "message" => "Token invalidado"
                    ]]
                ];
                Flight::json($response, 401);
                return;
            }

            // Preparamos y ejecutamos la consulta para contar los usuarios
            $query = $this->db->prepare("SELECT COUNT(id_usuario) as user_count FROM usuario;");
            $query->execute();

            // Obtenemos el resultado de la consulta
            $result = $query->fetch();

            // Armamos la respuesta
            $response = [
                "status" => "200 OK",
                "body" => [
                    "data" => [
                        "user_count" => $result['user_count']
                    ]
                ]
            ];

            Flight::json($response, 200); // Enviar como JSON con código 200

        }else{
            // Respuesta en caso de error de autenticación
            $response = [
                "status" => "401 Unauthorized",
                "body" => ["data" => [
                    "message" => "No se puede validar su identidad, por favor intente de nuevo",
                ]]
            ];
            Flight::json($response, 401); // Enviar como JSON con código 401
        }
    }

    function getAllActiveUsers(){

        // Si el token ya ha expirado o no es valido mandamos el error
        if(!validateToken() == null){

            // Obtener el token sin el prefijo "Bearer" directamente desde los headers
            $headers = apache_request_headers();
            $authorization = $headers["Authorization"] ?? "";
            $token = str_replace("Bearer ", "", $authorization);

            // Comprobar si el token está en la lista negra
            $checkQuery = $this->db->prepare("SELECT COUNT(*) FROM lista_negra WHERE token_invalido = :token");
            $checkQuery->execute([":token" => $token]);
            $isBlacklisted = $checkQuery->fetchColumn();

            if ($isBlacklisted > 0) {
                // Respuesta en caso de que el token esté en la lista negra
                $response = [
                    "status" => "401 Unauthorized",
                    "body" => ["data" => [
                        "message" => "Token invalidado"
                    ]]
                ];
                Flight::json($response, 401);
                return;
            }

            // Preparar y ejecutar la consulta
            $query = $this->db->prepare("SELECT 
                usuario.id_usuario, 
                persona.nombre, 
                persona.apellido_paterno, 
                persona.apellido_materno, 
                persona.sexo,
                rol.nombre_rol,
                usuario.activo,
                usuario.nombre_usuario,
                rol.id_rol,
                usuario.cuenta_activa
                FROM usuario 
                JOIN usuario_rol ON usuario.id_usuario = usuario_rol.fk_id_usuario
                JOIN persona ON persona.id_persona = usuario.fk_id_persona
                JOIN rol ON usuario_rol.fk_id_rol = rol.id_rol
                WHERE usuario.activo = true AND persona.activo = true AND usuario.cuenta_activa = true");
            $query->execute();

            // Obtenemos los datos de los usuarios
            $users = $query->fetchAll();

            if (empty($users)) {
                $response = [
                    "status" => "404 Not Found",
                    "body" => ["data" => [
                        "message" => "No se encontraron usuarios activos para mostrar."
                    ]]
                ];
                Flight::json($response, 404);
                return;
            }

            // Inicializamos el arreglo de respuesta
            $response = [
                "status" => "200 OK",
                "body" => [
                    "data" => []
                ]
            ];

            // Recorremos los resultados de la consulta y los guardamos en el arreglo de datos
            foreach($users as $row){
                $response["body"]["data"][] = [
                    "id_usuario" => $row['id_usuario'],
                    "nombre" => $row['nombre'],
                    "apellido_paterno" => $row['apellido_paterno'],
                    "apellido_materno" => $row['apellido_materno'],
                    "sexo" => $row['sexo'],
                    "activo" => $row['activo'],
                    "nombre_usuario" => $row['nombre_usuario'],
                    "id_rol" => $row['id_rol'],
                    "nombre_rol" => $row['nombre_rol']
                ];
            }

            Flight::json($response, 200); // Enviar como JSON con código 200

        }else{
            // Respuesta en caso de error por token expirado o inexistente
            $response = [
                "status" => "401 Unauthorized",
                "body" => ["data" => [
                    "message" => "No se puede validar su identidad, por favor intente de nuevo",
                ]]
            ];
            Flight::json($response, 401); // Enviar como JSON con código 401
        }

    }

    // Generar el codgio de la activación de cuenta
    private function generateActivationCode($length = 6) {
        return substr(str_shuffle(str_repeat('0123456789', $length)), 0, $length);
    }

    function createUser(){
         // Si el token ya ha expirado o no es valido mandamos el error
         if(!validateToken() == null){

            // Obtener el token sin el prefijo "Bearer" directamente desde los headers
            $headers = apache_request_headers();
            $authorization = $headers["Authorization"] ?? "";
            $token = str_replace("Bearer ", "", $authorization);

            // Comprobar si el token está en la lista negra
            $checkQuery = $this->db->prepare("SELECT COUNT(*) FROM lista_negra WHERE token_invalido = :token");
            $checkQuery->execute([":token" => $token]);
            $isBlacklisted = $checkQuery->fetchColumn();

            if ($isBlacklisted > 0) {
                // Respuesta en caso de que el token esté en la lista negra
                $response = [
                    "status" => "401 Unauthorized",
                    "body" => ["data" => [
                        "message" => "Token invalidado"
                    ]]
                ];
                Flight::json($response, 401);
                return;
            }

            // Obtener los datos enviados desde el cliente
            $request = Flight::request()->data;
    
            // Validar que todos los campos requeridos estén presentes
            if (
                empty($request['nombre']) ||
                empty($request['apellido_paterno']) ||
                empty($request['apellido_materno']) ||
                empty($request['correo']) ||
                empty($request['sexo']) ||
                empty($request['nombre_usuario']) ||
                empty($request['password']) ||
                empty($request['id_rol'])
            ) {
                $response = [
                    "status" => "400 Bad Request",
                    "body" => ["data" => [
                        "message" => "Todos los campos son obligatorios."
                    ]]
                ];
                Flight::json($response, 400);
                return;
            }
    
            try {
                // Verificar si el nombre de usuario ya existe
                $checkQuery = $this->db->prepare("
                    SELECT COUNT(*) FROM usuario WHERE nombre_usuario = :nombre_usuario
                ");
                $checkQuery->execute([
                    ":nombre_usuario" => $request['nombre_usuario']
                ]);
                $exists = $checkQuery->fetchColumn();
    
                if ($exists > 0) {
                    // Responder con error si el nombre de usuario ya está en uso
                    $response = [
                        "status" => "409 Conflict",
                        "body" => ["data" => [
                            "message" => "El nombre de usuario ya está en uso. Por favor elija otro."
                        ]]
                    ];
                    Flight::json($response, 409);
                    return;
                }

                // Verificar si el correo electronico ya fue regsitrado
                $checkQuery = $this->db->prepare("
                    SELECT COUNT(*) FROM usuario WHERE correo = :correo
                ");
                $checkQuery->execute([
                    ":correo" => $request['correo']
                ]);
                $exists = $checkQuery->fetchColumn();
    
                if ($exists > 0) {
                    // Responder con error si el correo ya está en uso
                    $response = [
                        "status" => "409 Conflict",
                        "body" => ["data" => [
                            "message" => "Este correo ya está en uso. Por favor elija otro."
                        ]]
                    ];
                    Flight::json($response, 409);
                    return;
                }
    
                // Iniciar una transacción
                $this->db->beginTransaction();
    
                // Insertar datos en la tabla persona
                $personaQuery = $this->db->prepare("
                    INSERT INTO persona (nombre, apellido_paterno, apellido_materno, sexo, activo) 
                    VALUES (:nombre, :apellido_paterno, :apellido_materno, :sexo, :activo)
                    RETURNING id_persona
                ");
                $personaQuery->execute([
                    ":nombre" => $request['nombre'],
                    ":apellido_paterno" => $request['apellido_paterno'],
                    ":apellido_materno" => $request['apellido_materno'],
                    ":sexo" => $request['sexo'],
                    ":activo" => true // Se establece como true
                ]);
                $id_persona = $personaQuery->fetchColumn();

                $codigo_activacion = $this -> generateActivationCode();
                $fecha_expiracion_activacion = date('Y-m-d H:i:s', strtotime('+2 minutes')); // Expira en 10 minutos

                // Insertar datos en la tabla usuario
                $usuarioQuery = $this->db->prepare("
                    INSERT INTO usuario (nombre_usuario, password, fk_id_persona, activo, correo, cuenta_activa, codigo_activacion, fecha_expiracion_activacion) 
                    VALUES (:nombre_usuario, :password, :fk_id_persona, :activo, :correo, :cuenta_activa, :codigo_activacion, :fecha_expiracion_activacion)
                    RETURNING id_usuario
                ");
                $usuarioQuery->execute([
                    ":nombre_usuario" => $request['nombre_usuario'],
                    ":password" => password_hash($request['password'], PASSWORD_DEFAULT), // Encriptar contraseña
                    ":fk_id_persona" => $id_persona,
                    ":activo" => true, // Activo se establece como true
                    ":correo" => $request['correo'],
                    ":cuenta_activa" => 0, // Cuenta_Activa se establece como false
                    ":codigo_activacion" => $codigo_activacion,
                    ":fecha_expiracion_activacion" => $fecha_expiracion_activacion
                ]);
                $id_usuario = $usuarioQuery->fetchColumn();
    
                // Insertar datos en la tabla usuario_rol
                $usuarioRolQuery = $this->db->prepare("
                    INSERT INTO usuario_rol (fk_id_usuario, fk_id_rol) 
                    VALUES (:fk_id_usuario, :fk_id_rol)
                ");
                $usuarioRolQuery->execute([
                    ":fk_id_usuario" => $id_usuario,
                    ":fk_id_rol" => $request['id_rol']
                ]);
    
                // Confirmar la transacción
                $this->db->commit();
    
                // Responder con éxito
                $response = [
                    "status" => "200 OK",
                    "body" => ["data" => [
                        "message" => "Usuario creado exitosamente."
                    ]]
                ];
                Flight::json($response, 200);
    
            } catch (Exception $e) {
                // Revertir la transacción en caso de error
                $this->db->rollBack();
    
                // Responder con error
                $response = [
                    "status" => "500 Internal Server Error",
                    "body" => ["data" => [
                        "message" => "Error al crear el usuario.",
                        "error" => $e->getMessage()
                    ]]
                ];
                Flight::json($response, 500);
            }
        } else {
            // Respuesta en caso de token inválido o expirado
            $response = [
                "status" => "401 Unauthorized",
                "body" => ["data" => [
                    "message" => "No se puede validar su identidad, por favor intente de nuevo"
                ]]
            ];
            Flight::json($response, 401);
        }
    }

    function editUserById($id_usuario){
        // Validar que el ID sea un número entero y contenga menos de 11 digitos (son los digitos maximos que soporta PostgreSQL para los campos tipo SERIAL) 
        if (!is_numeric($id_usuario) || intval($id_usuario) <= 0 || strlen($id_usuario) > 10 || intval($id_usuario) >= 2147483647) {
            $response = [
                "status" => "400 Bad Request",
                "body" => ["data" => [
                    "message" => "El ID de usuario es un parámetro inválido"
                ]]
            ];
            Flight::json($response, 400);
            return;
        }

        if (!validateToken() == null) {
            // Obtener el token sin el prefijo "Bearer" directamente desde los headers
            $headers = apache_request_headers();
            $authorization = $headers["Authorization"] ?? "";
            $token = str_replace("Bearer ", "", $authorization);
    
            // Comprobar si el token está en la lista negra
            $checkQuery = $this->db->prepare("SELECT COUNT(*) FROM lista_negra WHERE token_invalido = :token");
            $checkQuery->execute([":token" => $token]);
            $isBlacklisted = $checkQuery->fetchColumn();
    
            if ($isBlacklisted > 0) {
                $response = [
                    "status" => "401 Unauthorized",
                    "body" => ["data" => [
                        "message" => "Token invalidado"
                    ]]
                ];
                Flight::json($response, 401);
                return;
            }

            // Obtener los datos enviados desde el cliente
            $request = Flight::request()->data;
    
            // Validar que el ID de usuario y los campos requeridos estén presentes
            if (
                empty($request['nombre']) ||
                empty($request['apellido_paterno']) ||
                empty($request['apellido_materno']) ||
                empty($request['sexo']) ||
                empty($request['nombre_usuario']) ||
                empty($request['id_rol'])
            ) {
                $response = [
                    "status" => "400 Bad Request",
                    "body" => ["data" => [
                        "message" => "Todos los campos son obligatorios."
                    ]]
                ];
                Flight::json($response, 400);
                return;
            }
    
            try {
                // Verificar si el usuario existe
                $checkUserQuery = $this->db->prepare("SELECT COUNT(*) FROM usuario WHERE id_usuario = :id_usuario");
                $checkUserQuery->execute([":id_usuario" => intval($id_usuario)]);
                $userExists = $checkUserQuery->fetchColumn();

                if ($userExists == 0) {
                    $response = [
                        "status" => "404 Not Found",
                        "body" => ["data" => [
                            "message" => "El usuario con ID $id_usuario no fue encontrado"
                        ]]
                    ];
                    Flight::json($response, 404);
                    return;
                }
                // Continuar con el resto del código si el usuario existe...

                // Verificar si el nombre de usuario ya existe y no pertenece al usuario actual
                $checkUsernameQuery = $this->db->prepare("
                    SELECT COUNT(*) FROM usuario 
                    WHERE nombre_usuario = :nombre_usuario AND id_usuario != :id_usuario
                ");
                $checkUsernameQuery->execute([
                    ":nombre_usuario" => $request['nombre_usuario'],
                    ":id_usuario" => $id_usuario
                ]);
                $usernameExists = $checkUsernameQuery->fetchColumn();
    
                if ($usernameExists > 0) {
                    $response = [
                        "status" => "409 Conflict",
                        "body" => ["data" => [
                            "message" => "El nombre de usuario ya está en uso. Por favor elija otro."
                        ]]
                    ];
                    Flight::json($response, 409);
                    return;
                }
    
                // Iniciar una transacción
                $this->db->beginTransaction();
    
                // Actualizar datos en la tabla persona
                $personaQuery = $this->db->prepare("
                    UPDATE persona 
                    SET nombre = :nombre, apellido_paterno = :apellido_paterno, 
                        apellido_materno = :apellido_materno, sexo = :sexo 
                    WHERE id_persona = (
                        SELECT fk_id_persona FROM usuario WHERE id_usuario = :id_usuario
                    )
                ");
                $personaQuery->execute([
                    ":nombre" => $request['nombre'],
                    ":apellido_paterno" => $request['apellido_paterno'],
                    ":apellido_materno" => $request['apellido_materno'],
                    ":sexo" => $request['sexo'],
                    ":id_usuario" => $id_usuario
                ]);
    
                // Actualizar datos en la tabla usuario
                $updatePassword = "";
                $queryParams = [
                    ":nombre_usuario" => $request['nombre_usuario'],
                    ":id_usuario" => $id_usuario
                ];
    
                $usuarioQuery = $this->db->prepare("
                    UPDATE usuario 
                    SET nombre_usuario = :nombre_usuario
                    WHERE id_usuario = :id_usuario
                ");
                $usuarioQuery->execute($queryParams);
    
                // Actualizar datos en la tabla usuario_rol
                $usuarioRolQuery = $this->db->prepare("
                    UPDATE usuario_rol 
                    SET fk_id_rol = :id_rol 
                    WHERE fk_id_usuario = :id_usuario
                ");
                $usuarioRolQuery->execute([
                    ":id_rol" => $request['id_rol'],
                    ":id_usuario" => $id_usuario
                ]);
    
                // Confirmar la transacción
                $this->db->commit();
    
                // Responder con éxito
                $response = [
                    "status" => "200 OK",
                    "body" => ["data" => [
                        "message" => "Usuario editado exitosamente."
                    ]]
                ];
                Flight::json($response, 200);
    
            } catch (Exception $e) {
                // Revertir la transacción en caso de error
                $this->db->rollBack();
    
                // Responder con error
                $response = [
                    "status" => "500 Internal Server Error",
                    "body" => ["data" => [
                        "message" => "Error al editar el usuario.",
                        "error" => $e->getMessage()
                    ]]
                ];
                Flight::json($response, 500);
            }
        } else {
            $response = [
                "status" => "401 Unauthorized",
                "body" => ["data" => [
                    "message" => "No se puede validar su identidad, por favor intente de nuevo"
                ]]
            ];
            Flight::json($response, 401);
        }
    }
    
    function disableUserById($id_usuario){
        // Validar que el ID sea un número entero y contenga menos de 11 digitos (son los digitos maximos que soporta PostgreSQL para los campos tipo SERIAL) 
        if (!is_numeric($id_usuario) || intval($id_usuario) <= 0 || strlen($id_usuario) > 10 || intval($id_usuario) > 2147483647) {
                    $response = [
                        "status" => "400 Bad Request",
                        "body" => ["data" => [
                            "message" => "El ID de usuario es un parámetro inválido"
                        ]]
                    ];
            Flight::json($response, 400);
            return;
        }

        // Si el token ya ha expirado o no es válido, enviamos un error
        if (!validateToken() == null) {
    
            // Obtener el token sin el prefijo "Bearer" directamente desde los headers
            $headers = apache_request_headers();
            $authorization = $headers["Authorization"] ?? "";
            $token = str_replace("Bearer ", "", $authorization);
    
            // Comprobar si el token está en la lista negra
            $checkQuery = $this->db->prepare("SELECT COUNT(*) FROM lista_negra WHERE token_invalido = :token");
            $checkQuery->execute([":token" => $token]);
            $isBlacklisted = $checkQuery->fetchColumn();
    
            if ($isBlacklisted > 0) {
                // Respuesta en caso de que el token esté en la lista negra
                $response = [
                    "status" => "401 Unauthorized",
                    "body" => ["data" => [
                        "message" => "Token invalidado"
                    ]]
                ];
                Flight::json($response, 401);
                return;
            }
    
            // Obtener los datos enviados desde el cliente
            $request = Flight::request()->data;
    
            // Validar que el campo 'id_usuario' esté presente y no vacío
            if (empty($id_usuario)) {
                $response = [
                    "status" => "400 Bad Request",
                    "body" => ["data" => [
                        "message" => "Todos los campos son obligatorio."
                    ]]
                ];
                Flight::json($response, 400);
                return;
            }
    
            // Verificar si el usuario existe en la base de datos
            $userCheckQuery = $this->db->prepare("SELECT COUNT(*) FROM usuario WHERE id_usuario = :id_usuario");
            $userCheckQuery->execute([":id_usuario" => intval($id_usuario)]);
            $userExists = $userCheckQuery->fetchColumn();
    
            if ($userExists == 0) {
                // Responder con error si el usuario no existe
                $response = [
                    "status" => "404 Not Found",
                    "body" => ["data" => [
                        "message" => "El usuario con ID $id_usuario no fue encontrado"
                    ]]
                ];
                Flight::json($response, 404);
                return;
            }
    
            // Verificar si el usuario ya está desactivado
            $userStatusQuery = $this->db->prepare("SELECT activo FROM usuario WHERE id_usuario = :id_usuario");
            $userStatusQuery->execute([":id_usuario" => intval($id_usuario)]);
            $userStatus = $userStatusQuery->fetchColumn();
    
            if ($userStatus == false) {
                // Responder con error si el usuario ya está desactivado
                $response = [
                    "status" => "400 Bad Request",
                    "body" => ["data" => [
                        "message" => "El usuario ya está desactivado."
                    ]]
                ];
                Flight::json($response, 400);
                return;
            }
    
            try {
                // Iniciar una transacción
                $this->db->beginTransaction();
    
                // Actualizar el campo activo en la tabla usuario
                $usuarioQuery = $this->db->prepare("
                    UPDATE usuario
                    SET activo = false,
                        cuenta_activa = false
                    WHERE id_usuario = :id_usuario
                ");
                $usuarioQuery->execute([":id_usuario" => intval($id_usuario)]);
    
                // Actualizar el campo activo en la tabla persona
                $personaQuery = $this->db->prepare("
                    UPDATE persona
                    SET activo = false
                    WHERE id_persona = (
                        SELECT fk_id_persona
                        FROM usuario
                        WHERE id_usuario = :id_usuario
                    )
                ");
                $personaQuery->execute([":id_usuario" => intval($id_usuario)]);
    
                // Confirmar la transacción
                $this->db->commit();
    
                // Responder con éxito
                $response = [
                    "status" => "200 OK",
                    "body" => ["data" => [
                        "message" => "Usuario desactivado exitosamente."
                    ]]
                ];
                Flight::json($response, 200);
    
            } catch (Exception $e) {
                // Revertir la transacción en caso de error
                $this->db->rollBack();
    
                // Responder con error
                $response = [
                    "status" => "500 Internal Server Error",
                    "body" => ["data" => [
                        "message" => "Error al desactivar el usuario.",
                        "error" => $e->getMessage()
                    ]]
                ];
                Flight::json($response, 500);
            }
        } else {
            // Respuesta en caso de token inválido o expirado
            $response = [
                "status" => "401 Unauthorized",
                "body" => ["data" => [
                    "message" => "No se puede validar su identidad, por favor intente de nuevo"
                ]]
            ];
            Flight::json($response, 401);
        }
    }       
    
    function getCountAllActiveUsers(){

        // Validamos el token de autenticación
        if(!validateToken() == null){

            // Obtener el token sin el prefijo "Bearer" directamente desde los headers
            $headers = apache_request_headers();
            $authorization = $headers["Authorization"] ?? "";
            $token = str_replace("Bearer ", "", $authorization);
    
            // Comprobar si el token está en la lista negra
            $checkQuery = $this->db->prepare("SELECT COUNT(*) FROM lista_negra WHERE token_invalido = :token");
            $checkQuery->execute([":token" => $token]);
            $isBlacklisted = $checkQuery->fetchColumn();
    
            if ($isBlacklisted > 0) {
                // Respuesta en caso de que el token esté en la lista negra
                $response = [
                    "status" => "401 Unauthorized",
                    "body" => ["data" => [
                        "message" => "Token invalidado"
                    ]]
                ];
                Flight::json($response, 401);
                return;
            }

            // Preparamos y ejecutamos la consulta para contar los usuarios
            $query = $this->db->prepare("SELECT COUNT(id_usuario) as user_count FROM usuario WHERE activo = true;");
            $query->execute();

            // Obtenemos el resultado de la consulta
            $result = $query->fetch();

            // Armamos la respuesta
            $response = [
                "status" => "200 OK",
                "body" => [
                    "data" => [
                        "user_count" => $result['user_count']
                    ]
                ]
            ];

            Flight::json($response, 200); // Enviar como JSON con código 200

        }else{
            // Respuesta en caso de error de autenticación
            $response = [
                "status" => "401 Unauthorized",
                "body" => ["data" => [
                    "message" => "No se puede validar su identidad, por favor intente de nuevo",
                ]]
            ];
            Flight::json($response, 401); // Enviar como JSON con código 401
        }

    }

    function getCountAllActiveSecretaries(){

                // Validamos el token de autenticación
        if(!validateToken() == null){

            // Obtener el token sin el prefijo "Bearer" directamente desde los headers
            $headers = apache_request_headers();
            $authorization = $headers["Authorization"] ?? "";
            $token = str_replace("Bearer ", "", $authorization);
    
            // Comprobar si el token está en la lista negra
            $checkQuery = $this->db->prepare("SELECT COUNT(*) FROM lista_negra WHERE token_invalido = :token");
            $checkQuery->execute([":token" => $token]);
            $isBlacklisted = $checkQuery->fetchColumn();
    
            if ($isBlacklisted > 0) {
                // Respuesta en caso de que el token esté en la lista negra
                $response = [
                    "status" => "401 Unauthorized",
                    "body" => ["data" => [
                        "message" => "Token invalidado"
                    ]]
                ];
                Flight::json($response, 401);
                return;
            }

            // Preparamos y ejecutamos la consulta para contar las secretarias
            $query = $this->db->prepare("SELECT COUNT(id_usuario) as secretaries_count FROM usuario u
            INNER JOIN usuario_rol ur ON ur.fk_id_usuario = u.id_usuario
            INNER JOIN rol r ON r.id_rol = ur.fk_id_rol
            WHERE r.nombre_rol != 'Administrador' AND u.activo = true
            ;");
            $query->execute();

            // Obtenemos el resultado de la consulta
            $result = $query->fetch();

            // Armamos la respuesta
            $response = [
                "status" => "200 OK",
                "body" => [
                    "data" => [
                        "secretaries_count" => $result['secretaries_count']
                    ]
                ]
            ];

            Flight::json($response, 200); // Enviar como JSON con código 200

        }else{
            // Respuesta en caso de error de autenticación
            $response = [
                "status" => "401 Unauthorized",
                "body" => ["data" => [
                    "message" => "No se puede validar su identidad, por favor intente de nuevo",
                ]]
            ];
            Flight::json($response, 401); // Enviar como JSON con código 401
        }

    }

    function editUserPasswordById($id_usuario) {
        // Validar que el ID sea un número entero y contenga menos de 11 dígitos
        if (!is_numeric($id_usuario) || intval($id_usuario) <= 0 || strlen($id_usuario) > 10 || intval($id_usuario) > 2147483647) {
            $response = [
                "status" => "400 Bad Request",
                "body" => ["data" => [
                    "message" => "El ID de usuario es un parámetro inválido"
                ]]
            ];
            Flight::json($response, 400);
            return;
        }
    
        // Validar el token de autenticación
        if (!validateToken() == null) {
            // Obtener el token sin el prefijo "Bearer" directamente desde los headers
            $headers = apache_request_headers();
            $authorization = $headers["Authorization"] ?? "";
            $token = str_replace("Bearer ", "", $authorization);
    
            // Comprobar si el token está en la lista negra
            $checkQuery = $this->db->prepare("SELECT COUNT(*) FROM lista_negra WHERE token_invalido = :token");
            $checkQuery->execute([":token" => $token]);
            $isBlacklisted = $checkQuery->fetchColumn();
    
            if ($isBlacklisted > 0) {
                $response = [
                    "status" => "401 Unauthorized",
                    "body" => ["data" => [
                        "message" => "Token invalidado"
                    ]]
                ];
                Flight::json($response, 401);
                return;
            }
    
            // Obtener los datos enviados desde el cliente
            $request = Flight::request()->data;
    
            // Validar que ambos campos estén presentes y no estén vacíos
            if (empty($request['contrasena']) || empty($request['confirmar_contrasena'])) {
                $response = [
                    "status" => "400 Bad Request",
                    "body" => ["data" => [
                        "message" => "Todos los campos son obligatorios."
                    ]]
                ];
                Flight::json($response, 400);
                return;
            }
    
            // Validar que las contraseñas coincidan
            if ($request['contrasena'] !== $request['confirmar_contrasena']) {
                $response = [
                    "status" => "400 Bad Request",
                    "body" => ["data" => [
                        "message" => "Las contraseñas no coinciden."
                    ]]
                ];
                Flight::json($response, 400);
                return;
            }
    
            try {
                // Verificar si el usuario existe en la base de datos
                $checkUserQuery = $this->db->prepare("SELECT COUNT(*) FROM usuario WHERE id_usuario = :id_usuario");
                $checkUserQuery->execute([":id_usuario" => intval($id_usuario)]);
                $userExists = $checkUserQuery->fetchColumn();
    
                if ($userExists == 0) {
                    $response = [
                        "status" => "404 Not Found",
                        "body" => ["data" => [
                            "message" => "El usuario con ID $id_usuario no fue encontrado."
                        ]]
                    ];
                    Flight::json($response, 404);
                    return;
                }
    
                // Iniciar una transacción
                $this->db->beginTransaction();
    
                // Encriptar la contraseña
                $hashedPassword = password_hash($request['contrasena'], PASSWORD_DEFAULT);
    
                // Actualizar la contraseña en la tabla usuario
                $updateQuery = $this->db->prepare("
                    UPDATE usuario
                    SET password = :password
                    WHERE id_usuario = :id_usuario
                ");
                $updateQuery->execute([
                    ":password" => $hashedPassword,
                    ":id_usuario" => intval($id_usuario)
                ]);
    
                // Confirmar la transacción
                $this->db->commit();
    
                // Responder con éxito
                $response = [
                    "status" => "200 OK",
                    "body" => ["data" => [
                        "message" => "Contraseña actualizada exitosamente."
                    ]]
                ];
                Flight::json($response, 200);
    
            } catch (Exception $e) {
                // Revertir la transacción en caso de error
                $this->db->rollBack();
    
                // Responder con error
                $response = [
                    "status" => "500 Internal Server Error",
                    "body" => ["data" => [
                        "message" => "Error al actualizar la contraseña.",
                        "error" => $e->getMessage()
                    ]]
                ];
                Flight::json($response, 500);
            }
        } else {
            // Respuesta en caso de token inválido o expirado
            $response = [
                "status" => "401 Unauthorized",
                "body" => ["data" => [
                    "message" => "No se puede validar su identidad, por favor intente de nuevo."
                ]]
            ];
            Flight::json($response, 401);
        }
    }
    

    function registerUser(){

            // Obtener los datos enviados desde el cliente
            $request = Flight::request()->data;
    
            // Validar que todos los campos requeridos estén presentes
            if (
                empty($request['nombre']) ||
                empty($request['apellido_paterno']) ||
                empty($request['apellido_materno']) ||
                empty($request['correo']) ||
                empty($request['sexo']) ||
                empty($request['nombre_usuario']) ||
                empty($request['password']) ||
                empty($request['id_rol'])
            ) {
                $response = [
                    "status" => "400 Bad Request",
                    "body" => ["data" => [
                        "message" => "Todos los campos son obligatorios."
                    ]]
                ];
                Flight::json($response, 400);
                return;
            }
    
            try {
                // Verificar si el nombre de usuario ya existe
                $checkQuery = $this->db->prepare("
                    SELECT COUNT(*) FROM usuario WHERE nombre_usuario = :nombre_usuario
                ");
                $checkQuery->execute([
                    ":nombre_usuario" => $request['nombre_usuario']
                ]);
                $exists = $checkQuery->fetchColumn();
    
                if ($exists > 0) {
                    // Responder con error si el nombre de usuario ya está en uso
                    $response = [
                        "status" => "409 Conflict",
                        "body" => ["data" => [
                            "message" => "El nombre de usuario ya está en uso. Por favor elija otro."
                        ]]
                    ];
                    Flight::json($response, 409);
                    return;
                }

                // Verificar si el correo electronico ya fue regsitrado
                $checkQuery = $this->db->prepare("
                    SELECT COUNT(*) FROM usuario WHERE correo = :correo
                ");
                $checkQuery->execute([
                    ":correo" => $request['correo']
                ]);
                $exists = $checkQuery->fetchColumn();
    
                if ($exists > 0) {
                    // Responder con error si el correo ya está en uso
                    $response = [
                        "status" => "409 Conflict",
                        "body" => ["data" => [
                            "message" => "Este correo ya está en uso. Por favor elija otro."
                        ]]
                    ];
                    Flight::json($response, 409);
                    return;
                }
    
                // Iniciar una transacción
                $this->db->beginTransaction();
    
                // Insertar datos en la tabla persona
                $personaQuery = $this->db->prepare("
                    INSERT INTO persona (nombre, apellido_paterno, apellido_materno, sexo, activo) 
                    VALUES (:nombre, :apellido_paterno, :apellido_materno, :sexo, :activo)
                    RETURNING id_persona
                ");
                $personaQuery->execute([
                    ":nombre" => $request['nombre'],
                    ":apellido_paterno" => $request['apellido_paterno'],
                    ":apellido_materno" => $request['apellido_materno'],
                    ":sexo" => $request['sexo'],
                    ":activo" => true // Se establece como true
                ]);
                $id_persona = $personaQuery->fetchColumn();

                $codigo_activacion = $this -> generateActivationCode();
                $fecha_expiracion_activacion = date('Y-m-d H:i:s', strtotime('+2 minutes')); // Expira en 10 minutos

                // Insertar datos en la tabla usuario
                $usuarioQuery = $this->db->prepare("
                    INSERT INTO usuario (nombre_usuario, password, fk_id_persona, activo, correo, cuenta_activa, codigo_activacion, fecha_expiracion_activacion) 
                    VALUES (:nombre_usuario, :password, :fk_id_persona, :activo, :correo, :cuenta_activa, :codigo_activacion, :fecha_expiracion_activacion)
                    RETURNING id_usuario
                ");
                $usuarioQuery->execute([
                    ":nombre_usuario" => $request['nombre_usuario'],
                    ":password" => password_hash($request['password'], PASSWORD_DEFAULT), // Encriptar contraseña
                    ":fk_id_persona" => $id_persona,
                    ":activo" => true, // Activo se establece como true
                    ":correo" => $request['correo'],
                    ":cuenta_activa" => 0, // Cuenta_Activa se establece como false
                    ":codigo_activacion" => $codigo_activacion,
                    ":fecha_expiracion_activacion" => $fecha_expiracion_activacion
                ]);
                $id_usuario = $usuarioQuery->fetchColumn();
    
                // Insertar datos en la tabla usuario_rol
                $usuarioRolQuery = $this->db->prepare("
                    INSERT INTO usuario_rol (fk_id_usuario, fk_id_rol) 
                    VALUES (:fk_id_usuario, :fk_id_rol)
                ");
                $usuarioRolQuery->execute([
                    ":fk_id_usuario" => $id_usuario,
                    ":fk_id_rol" => $request['id_rol']
                ]);
    
                // Confirmar la transacción
                $this->db->commit();
    
                // Responder con éxito junto al ID encriptado
                $response = [
                    "status" => "200 OK",
                    "body" => ["data" => [
                        "message" => "Usuario creado exitosamente.",
                        "id_usuario" => $id_usuario
                    ]]
                ];
                Flight::json($response, 200);
    
            } catch (Exception $e) {
                // Revertir la transacción en caso de error
                $this->db->rollBack();
    
                // Responder con error
                $response = [
                    "status" => "500 Internal Server Error",
                    "body" => ["data" => [
                        "message" => "Error al crear el usuario.",
                        "error" => $e->getMessage()
                    ]]
                ];
                Flight::json($response, 500);
            }

    }

    function activateAccount($id_usuario){

        $request = Flight::request()->data;

        // Validar campos
        if (empty($request['codigo_activacion'])) {
            Flight::json([
                "status" => "400 Bad Request",
                "body" => ["data" => ["message" => "Código de activación es requerido"]]
            ], 400);
            return;
        }

        try {
            // Primero buscar el usuario por ID para obtener el correo
            $userQuery = $this->db->prepare("
                SELECT id_usuario, correo, fecha_expiracion_activacion, codigo_activacion, cuenta_activa
                FROM usuario 
                WHERE id_usuario = :id_usuario
            ");
            $userQuery->execute([":id_usuario" => $id_usuario]);
            
            if ($userQuery->rowCount() === 0) {
                Flight::json([
                    "status" => "404 Not Found",
                    "body" => ["data" => ["message" => "Usuario no encontrado"]]
                ], 404);
                return;
            }

            $usuario = $userQuery->fetch();
            
            // Verificar si la cuenta ya está activa
            if ($usuario['cuenta_activa']) {
                Flight::json([
                    "status" => "400 Bad Request",
                    "body" => ["data" => ["message" => "La cuenta ya está activada"]]
                ], 400);
                return;
            }

            // Verificar el código de activación
            if ($usuario['codigo_activacion'] !== $request['codigo_activacion']) {
                Flight::json([
                    "status" => "400 Bad Request",
                    "body" => ["data" => ["message" => "Código de activación inválido"]]
                ], 400);
                return;
            }

            // Verificar si el código expiró
            if (strtotime($usuario['fecha_expiracion_activacion']) < time()) {
                Flight::json([
                    "status" => "400 Bad Request",
                    "body" => ["data" => ["message" => "El código de activación ha expirado"]]
                ], 400);
                return;
            }

            // Activar la cuenta
            $updateQuery = $this->db->prepare("
                UPDATE usuario 
                SET cuenta_activa = true, 
                    codigo_activacion = NULL,
                    fecha_expiracion_activacion = NULL
                WHERE id_usuario = :id_usuario
            ");
            $updateQuery->execute([":id_usuario" => $id_usuario]);

            Flight::json([
                "status" => "200 OK",
                "body" => ["data" => ["message" => "Cuenta activada exitosamente"]]
            ], 200);

        } catch (Exception $e) {
            Flight::json([
                "status" => "500 Internal Server Error",
                "body" => ["data" => [
                    "message" => "Error al activar la cuenta",
                    "error" => $e->getMessage()
                ]]
            ], 500);
        }

    }

    function sendActivationCode($id_usuario){

                try {
            // Buscar el usuario por ID para obtener sus datos
            $userQuery = $this->db->prepare("
                SELECT id_usuario, correo, nombre_usuario, codigo_activacion
                FROM usuario 
                WHERE id_usuario = :id_usuario AND cuenta_activa = false
            ");
            $userQuery->execute([":id_usuario" => $id_usuario]);
            
            if ($userQuery->rowCount() === 0) {
                Flight::json([
                    "status" => "404 Not Found",
                    "body" => ["data" => ["message" => "Usuario no encontrado o ya activado"]]
                ], 404);
                return;
            }

            $usuario = $userQuery->fetch();
            
            // Generar nuevo código si no existe o reenviar el existente
            $codigo_activacion = $usuario['codigo_activacion'] ?: $this->generateActivationCode();
            $fecha_expiracion = date('Y-m-d H:i:s', strtotime('+2 minutes'));

            // Actualizar el código en la base de datos
            $updateQuery = $this->db->prepare("
                UPDATE usuario 
                SET codigo_activacion = :codigo,
                    fecha_expiracion_activacion = :fecha_expiracion
                WHERE id_usuario = :id_usuario
            ");
            $updateQuery->execute([
                ":codigo" => $codigo_activacion,
                ":fecha_expiracion" => $fecha_expiracion,
                ":id_usuario" => $id_usuario
            ]);

            // Enviar el correo con PHPMailer
            $mailSent = $this->enviarCorreoActivacion(
                $usuario['correo'],
                $usuario['nombre_usuario'],
                $codigo_activacion
            );

            if ($mailSent) {
                Flight::json([
                    "status" => "200 OK",
                    "body" => ["data" => [
                        "message" => "Código de activación enviado exitosamente",
                        "correo" => $usuario['correo']
                    ]]
                ], 200);
            } else {
                Flight::json([
                    "status" => "500 Internal Server Error",
                    "body" => ["data" => ["message" => "Error al enviar el correo"]]
                ], 500);
            }

        } catch (Exception $e) {
            Flight::json([
                "status" => "500 Internal Server Error",
                "body" => ["data" => [
                    "message" => "Error al procesar la solicitud",
                    "error" => $e->getMessage()
                ]]
            ], 500);
        }
    }

    private function enviarCorreoActivacion($correo, $nombre_usuario, $codigo_activacion) {
        try {
            // Crear instancia de PHPMailer
            $mail = new PHPMailer\PHPMailer\PHPMailer(true);
            
            // Configuración del servidor SMTP
            $mail->isSMTP();
            $mail->Host = $_ENV['MAIL_HOST']; 
            $mail->SMTPAuth = true;
            $mail->Username = $_ENV['MAIL_USER']; 
            $mail->Password = $_ENV['MAIL_PASS']; 
            $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = $_ENV['MAIL_PORT']; 

            // Configuración de codificación de caracteres
            $mail->CharSet = 'UTF-8'; // Esta línea es crucial
            $mail->Encoding = 'base64'; // También ayuda con la codificación

            // Configuración del remitente y destinatario
            $mail->setFrom($_ENV['MAIL_USER'], 'Sistema de Activación');
            $mail->addAddress($correo, $nombre_usuario);
            
            // Contenido del correo
            $mail->isHTML(true);
            $mail->Subject = 'Código de Activación de Cuenta';
            
            $mail->Body = "
                <h2>Activación de Cuenta</h2>
                <p>Hola <strong>$nombre_usuario</strong>,</p>
                <p>Tu código de activación es:</p>
                <h1 style='font-size: 32px; color: #007bff;'>$codigo_activacion</h1>
                <p>Este código expira en 2 minutos.</p>
                <p>Si no solicitaste este registro, por favor ignora este correo.</p>
                <br>
                <p>Saludos,<br>Equipo de MiruGo</p>
            ";
            
            $mail->AltBody = "
                Activación de Cuenta
                
                Hola $nombre_usuario,
                
                Tu código de activación es: $codigo_activacion
                
                Este código expira en 2 minutos.
                
                Si no solicitaste este registro, por favor ignora este correo.
                
                Saludos,
                Equipo del Sistema
            ";

            // Enviar correo
            return $mail->send();
            
        } catch (Exception $e) {
            error_log("Error al enviar correo: " . $e->getMessage());
            return false;
        }

    }

    function resendActivationCodeById($id_usuario){

    try {
        // Buscar el usuario por ID
        $userQuery = $this->db->prepare("
            SELECT id_usuario, correo, nombre_usuario, cuenta_activa
            FROM usuario 
            WHERE id_usuario = :id_usuario
        ");
        $userQuery->execute([":id_usuario" => $id_usuario]);
        
        if ($userQuery->rowCount() === 0) {
            Flight::json([
                "status" => "404 Not Found",
                "body" => ["data" => [
                    "message" => "Usuario no encontrado",
                    "error_type" => "usuario_no_encontrado"
                ]]
            ], 404);
            return;
        }

        $usuario = $userQuery->fetch();
        
        // Verificar si la cuenta ya está activa
        if ($usuario['cuenta_activa']) {
            Flight::json([
                "status" => "400 Bad Request",
                "body" => ["data" => [
                    "message" => "La cuenta ya está activada",
                    "error_type" => "cuenta_ya_activada"
                ]]
            ], 400);
            return;
        }

        // Generar nuevo código de activación
        $codigo_activacion = $this->generateActivationCode();
        $fecha_expiracion = date('Y-m-d H:i:s', strtotime('+2 minutes'));

        // Actualizar el código en la base de datos
        $updateQuery = $this->db->prepare("
            UPDATE usuario 
            SET codigo_activacion = :codigo,
                fecha_expiracion_activacion = :fecha_expiracion
            WHERE id_usuario = :id_usuario
        ");
        $updateQuery->execute([
            ":codigo" => $codigo_activacion,
            ":fecha_expiracion" => $fecha_expiracion,
            ":id_usuario" => $id_usuario
        ]);

        // Enviar el correo con el nuevo código
        $mailSent = $this->enviarCorreoActivacion(
            $usuario['correo'],
            $usuario['nombre_usuario'],
            $codigo_activacion
        );

        if ($mailSent) {
            Flight::json([
                "status" => "200 OK",
                "body" => ["data" => [
                    "message" => "Nuevo código de activación enviado exitosamente",
                    "correo" => $usuario['correo']
                ]]
            ], 200);
        } else {
            Flight::json([
                "status" => "500 Internal Server Error",
                "body" => ["data" => [
                    "message" => "Error al enviar el correo electrónico"
                ]]
            ], 500);
        }

    } catch (Exception $e) {
        Flight::json([
            "status" => "500 Internal Server Error",
            "body" => ["data" => [
                "message" => "Error al procesar la solicitud",
                "error" => $e->getMessage()
            ]]
        ], 500);
    }

    }


    // FUNCIONES PARA LA RECUPERACION DE CONTRASEÑA MEDIANTE CORREO
    /**
     * Genera un token aleatorio seguro para la recuperación de contraseña.
     */
    private function generateResetToken($length = 32) {
        // Genera un token de 64 caracteres
        return bin2hex(random_bytes($length));
    }

/**
     * Envía el correo de recuperación usando PHPMailer.
     */
    private function enviarCorreoRecuperacion($correo, $nombre_usuario, $token_recuperacion) {
        try {
            // Crear instancia de PHPMailer
            $mail = new PHPMailer\PHPMailer\PHPMailer(true);
            
            // Configuración del servidor SMTP
            $mail->isSMTP();
            $mail->Host = $_ENV['MAIL_HOST']; 
            $mail->SMTPAuth = true;
            $mail->Username = $_ENV['MAIL_USER']; 
            $mail->Password = $_ENV['MAIL_PASS']; 
            $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = $_ENV['MAIL_PORT']; 

            // Configuración de codificación de caracteres
            $mail->CharSet = 'UTF-8';
            $mail->Encoding = 'base64';

            // Configuración del remitente y destinatario
            $mail->setFrom($_ENV['MAIL_USER'], 'Sistema de Recuperación');
            $mail->addAddress($correo, $nombre_usuario);
            
            // *** IMPORTANTE: Define la URL de tu frontend en tu archivo .env ***
            // Ejemplo: URL_FRONTEND=http://localhost:3000
            $urlRecuperacion = $_ENV['URL_FRONTEND'] . '/reset-password?token=' . $token_recuperacion;

            // Contenido del correo
            $mail->isHTML(true);
            $mail->Subject = 'Restablecimiento de Contraseña';
            
            // --- INICIO DEL CAMBIO ---
            $mail->Body = "
                <div style='font-family: Arial, sans-serif; line-height: 1.6;'>
                    <h2>Solicitud de Restablecimiento de Contraseña</h2>
                    <p>Hola <strong>$nombre_usuario</strong>,</p>
                    <p>Recibimos una solicitud para restablecer tu contraseña. Haz clic en el siguiente botón para continuar:</p>
                    <p style='text-align: center; margin: 20px 0;'>
                        <a href='$urlRecuperacion' 
                           style='background-color: #007bff; color: white; padding: 12px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;'>
                           Restablecer Contraseña
                        </a>
                    </p>
                    <p>Este enlace expira en 15 minutos.</p>
                    <p>Si no solicitaste este cambio, por favor ignora este correo.</p>
                    <br>
                    <hr style='border: none; border-top: 1px solid #eeeeee;'>
                    <p style='font-size: 12px; color: #777;'>
                        Si el botón no funciona, copie y pegue el siguiente enlace en su navegador:
                    </p>
                    <p style='font-size: 12px; color: #777;'>
                        <a href='$urlRecuperacion' style='color: #007bff;'>$urlRecuperacion</a>
                    </p>
                    <br>
                    <p style='font-size: 14px;'>Saludos,<br>Equipo de MiruGo</p>
                </div>
            ";
            // --- FIN DEL CAMBIO ---
            
            // El AltBody (versión de texto plano) ya incluye el enlace, así que está correcto.
            $mail->AltBody = "
                Restablecimiento de Contraseña
                
                Hola $nombre_usuario,
                
                Recibimos una solicitud para restablecer tu contraseña. Copia y pega la siguiente URL en tu navegador:
                $urlRecuperacion
                
                Este enlace expira en 15 minutos.
                
                Si no solicitaste este cambio, por favor ignora este correo.
                
                Saludos,
                Equipo del Sistema
            ";

            // Enviar correo
            return $mail->send();
            
        } catch (Exception $e) {
            error_log("Error al enviar correo de recuperación: " . $e->getMessage());
            return false;
        }
    }

/**
     * Endpoint 1: Solicitar recuperación de contraseña.
     * Recibe un correo, genera un token y envía el email.
     */
    function solicitarRecuperacion() {
        $request = Flight::request()->data;

        // Validar que se recibió el correo
        if (empty($request['correo'])) {
            Flight::json([
                "status" => "400 Bad Request",
                "body" => ["data" => ["message" => "El campo correo es obligatorio."]]
            ], 400);
            return;
        }

        try {
            // Buscar al usuario por correo
            $userQuery = $this->db->prepare("
                SELECT id_usuario, nombre_usuario, cuenta_activa, activo
                FROM usuario 
                WHERE correo = :correo
            ");
            $userQuery->execute([":correo" => $request['correo']]);

            if ($userQuery->rowCount() > 0) {
                $usuario = $userQuery->fetch();

                // Solo proceder si la cuenta está activa
                if ($usuario['activo'] && $usuario['cuenta_activa']) {
                    
                    // Generar token y fecha de expiración (ej. 15 minutos)
                    $token = $this->generateResetToken();
                    $fecha_expiracion = date('Y-m-d H:i:s', strtotime('+15 minutes'));

                    // Guardar el token en la BD
                    $updateQuery = $this->db->prepare("
                        UPDATE usuario 
                        SET token_recuperacion = :token,
                            fecha_expiracion_recuperacion = :fecha
                        WHERE id_usuario = :id_usuario
                    ");
                    $updateQuery->execute([
                        ":token" => $token,
                        ":fecha" => $fecha_expiracion,
                        ":id_usuario" => $usuario['id_usuario']
                    ]);

                    // Enviar el correo y verificar si fue exitoso
                    $mailSent = $this->enviarCorreoRecuperacion(
                        $request['correo'],
                        $usuario['nombre_usuario'],
                        $token
                    );

                    // *** ESTE ES EL CAMBIO QUE SOLICITASTE ***
                    if ($mailSent) {
                        // Si el correo se envió, retornamos la respuesta genérica
                        Flight::json([
                            "status" => "200 OK",
                            "body" => ["data" => [
                                "message" => "Si existe una cuenta asociada a este correo, se ha enviado un enlace de recuperación."
                            ]]
                        ], 200);
                        return; // Salimos de la función
                    } else {
                        // Si falló el envío, retornamos un error 500
                        Flight::json([
                            "status" => "500 Internal Server Error",
                            "body" => ["data" => [
                                "message" => "El sistema no pudo enviar el correo de recuperación. Por favor, intente de nuevo más tarde."
                            ]]
                        ], 500);
                        return; // Salimos de la función
                    }
                }
            }

            // Respuesta genérica por seguridad
            // Esta respuesta se envía si:
            // 1. El correo no se encontró.
            // 2. El usuario no estaba activo.
            Flight::json([
                "status" => "200 OK",
                "body" => ["data" => [
                    "message" => "Si existe una cuenta asociada a este correo, se ha enviado un enlace de recuperación."
                ]]
            ], 200);

        } catch (Exception $e) {
            Flight::json([
                "status" => "500 Internal Server Error",
                "body" => ["data" => [
                    "message" => "Error al procesar la solicitud.",
                    "error" => $e->getMessage()
                ]]
            ], 500);
        }
    }


    /**
     * Endpoint 2: Restablecer la contraseña.
     * Recibe el token (del enlace), la nueva contraseña y la confirmación.
     */
    function restablecerPasswordPorToken() {
        $request = Flight::request()->data;

        // Validar campos
        if (empty($request['token']) || empty($request['password']) || empty($request['confirmar_password'])) {
            Flight::json([
                "status" => "400 Bad Request",
                "body" => ["data" => ["message" => "Todos los campos son obligatorios (token, password, confirmar_password)."]]
            ], 400);
            return;
        }

        // Validar que las contraseñas coincidan
        if ($request['password'] !== $request['confirmar_password']) {
            Flight::json([
                "status" => "400 Bad Request",
                "body" => ["data" => ["message" => "Las contraseñas no coinciden."]]
            ], 400);
            return;
        }

        try {
            // Buscar usuario por el token de recuperación
            $userQuery = $this->db->prepare("
                SELECT id_usuario, fecha_expiracion_recuperacion 
                FROM usuario 
                WHERE token_recuperacion = :token AND activo = true
            ");
            $userQuery->execute([":token" => $request['token']]);

            if ($userQuery->rowCount() === 0) {
                Flight::json([
                    "status" => "400 Bad Request",
                    "body" => ["data" => ["message" => "Token inválido o expirado."]]
                ], 400);
                return;
            }

            $usuario = $userQuery->fetch();

            // Verificar si el token expiró
            if (strtotime($usuario['fecha_expiracion_recuperacion']) < time()) {
                Flight::json([
                    "status" => "400 Bad Request",
                    "body" => ["data" => ["message" => "El token de recuperación ha expirado. Por favor, solicita uno nuevo."]]
                ], 400);
                return;
            }

            // Todo en orden: Hashear la nueva contraseña
            $hashedPassword = password_hash($request['password'], PASSWORD_DEFAULT);

            // Actualizar la contraseña y anular el token
            $updateQuery = $this->db->prepare("
                UPDATE usuario 
                SET password = :password,
                    token_recuperacion = NULL,
                    fecha_expiracion_recuperacion = NULL
                WHERE id_usuario = :id_usuario
            ");
            $updateQuery->execute([
                ":password" => $hashedPassword,
                ":id_usuario" => $usuario['id_usuario']
            ]);

            Flight::json([
                "status" => "200 OK",
                "body" => ["data" => ["message" => "Contraseña actualizada exitosamente."]]
            ], 200);

        } catch (Exception $e) {
            Flight::json([
                "status" => "500 Internal Server Error",
                "body" => ["data" => [
                    "message" => "Error al actualizar la contraseña.",
                    "error" => $e->getMessage()
                ]]
            ], 500);
        }
    }

    function getCorreoUsuario($id_usuario){

        // Validar el token
        if(!validateToken() == null){
            
            // Obtener el token sin el prefijo "Bearer" directamente desde los headers
            $headers = apache_request_headers();
            $authorization = $headers["Authorization"] ?? "";
            $token = str_replace("Bearer ", "", $authorization);

            // Validar que el ID usuario sea numérico
            if (!is_numeric($id_usuario)) {
                $response = [
                    "status" => "400 Bad Request",
                    "body" => ["data" => [
                        "message" => "ID de usuario inválido"
                    ]]
                ];
                Flight::json($response, 400);
                return;
            }

            // Preparar y ejecutar la consulta para obtener el correo
            $query = $this->db->prepare("SELECT 
                correo 
                FROM usuario 
                WHERE id_usuario = :id_usuario
                AND activo = true");
            $query->execute([":id_usuario" => $id_usuario]);

            // Obtener el resultado
            $result = $query->fetch(PDO::FETCH_ASSOC);

            if ($result) {
                // Si se encontró el usuario, devolver el correo
                $response = [
                    "status" => "200 OK",
                    "body" => ["data" => [
                        "correo" => $result['correo']
                    ]]
                ];
                Flight::json($response, 200);
            } else {
                // Si no se encontró el usuario
                $response = [
                    "status" => "404 Not Found",
                    "body" => ["data" => [
                        "message" => "Usuario no encontrado"
                    ]]
                ];
                Flight::json($response, 404);
            }

        } else {
            // Respuesta en caso de error por token expirado o inexistente
            $response = [
                "status" => "401 Unauthorized",
                "body" => ["data" => [
                    "message" => "No se puede validar su identidad, por favor intente de nuevo",
                ]]
            ];
            Flight::json($response, 401);
        }

    }

public function ContarUsuarios() {
    try {
        // Construir consulta base SIN FILTROS
        $sql = "
            SELECT 
                COUNT(*) as total_usuarios,
                SUM(CASE WHEN u.activo = true THEN 1 ELSE 0 END) as usuarios_activos,
                SUM(CASE WHEN u.activo = false THEN 1 ELSE 0 END) as usuarios_inactivos,
                SUM(CASE WHEN u.cuenta_activa = true THEN 1 ELSE 0 END) as cuentas_activadas,
                SUM(CASE WHEN u.cuenta_activa = false THEN 1 ELSE 0 END) as cuentas_no_activadas,
                COUNT(DISTINCT ur.fk_id_rol) as total_roles
            FROM usuario u
            LEFT JOIN usuario_rol ur ON u.id_usuario = ur.fk_id_usuario
        ";
        
        // Ejecutar consulta principal SIN PARÁMETROS
        $query = $this->db->prepare($sql);
        $query->execute();
        $estadisticas = $query->fetch();
        
        // Obtener conteo por rol SIN FILTROS
        $sqlRoles = "
            SELECT 
                r.id_rol,
                r.nombre_rol,
                COUNT(ur.fk_id_usuario) as total_usuarios,
                SUM(CASE WHEN u.activo = true THEN 1 ELSE 0 END) as usuarios_activos
            FROM rol r
            LEFT JOIN usuario_rol ur ON r.id_rol = ur.fk_id_rol
            LEFT JOIN usuario u ON ur.fk_id_usuario = u.id_usuario
            WHERE r.activo = true
            GROUP BY r.id_rol, r.nombre_rol 
            ORDER BY total_usuarios DESC
        ";
        
        $queryRoles = $this->db->prepare($sqlRoles);
        $queryRoles->execute();
        $conteoPorRol = $queryRoles->fetchAll();
        
        // Obtener estadísticas de activación por correo SIN FILTROS
        $sqlActivacion = "
            SELECT 
                COUNT(*) as total_usuarios,
                SUM(CASE WHEN cuenta_activa = true THEN 1 ELSE 0 END) as cuentas_activadas,
                SUM(CASE WHEN cuenta_activa = false AND codigo_activacion IS NOT NULL THEN 1 ELSE 0 END) as pendientes_activacion,
                SUM(CASE WHEN token_recuperacion IS NOT NULL THEN 1 ELSE 0 END) as solicitudes_recuperacion
            FROM usuario
        ";
        
        $queryActivacion = $this->db->prepare($sqlActivacion);
        $queryActivacion->execute();
        $estadisticasActivacion = $queryActivacion->fetch();
        
        // Obtener usuarios con códigos de activación expirados SIN FILTROS
        $sqlCodigosExpirados = "
            SELECT 
                COUNT(*) as codigos_activacion_expirados
            FROM usuario
            WHERE codigo_activacion IS NOT NULL 
            AND fecha_expiracion_activacion < CURRENT_TIMESTAMP
            AND cuenta_activa = false
        ";
        
        $queryCodigosExpirados = $this->db->prepare($sqlCodigosExpirados);
        $queryCodigosExpirados->execute();
        $codigosExpirados = $queryCodigosExpirados->fetch();
        
        // Obtener usuarios con tokens de recuperación activos SIN FILTROS
        $sqlTokensRecuperacion = "
            SELECT 
                COUNT(*) as tokens_recuperacion_activos
            FROM usuario
            WHERE token_recuperacion IS NOT NULL 
            AND fecha_expiracion_recuperacion > CURRENT_TIMESTAMP
        ";
        
        $queryTokensRecuperacion = $this->db->prepare($sqlTokensRecuperacion);
        $queryTokensRecuperacion->execute();
        $tokensRecuperacion = $queryTokensRecuperacion->fetch();
        
        // Construir respuesta
        $response = [
            "status" => "200 OK",
            "body" => [
                "message" => "Estadísticas de usuarios obtenidas exitosamente",
                "data" => [
                    "estadisticas_generales" => [
                        "total_usuarios" => (int)$estadisticas['total_usuarios'],
                        "usuarios_activos" => (int)$estadisticas['usuarios_activos'],
                        "usuarios_inactivos" => (int)$estadisticas['usuarios_inactivos'],
                        "cuentas_activadas" => (int)$estadisticas['cuentas_activadas'],
                        "cuentas_no_activadas" => (int)$estadisticas['cuentas_no_activadas'],
                        "total_roles" => (int)$estadisticas['total_roles']
                    ],
                    "estadisticas_activacion" => [
                        "cuentas_activadas" => (int)$estadisticasActivacion['cuentas_activadas'],
                        "pendientes_activacion" => (int)$estadisticasActivacion['pendientes_activacion'],
                        "solicitudes_recuperacion" => (int)$estadisticasActivacion['solicitudes_recuperacion'],
                        "codigos_activacion_expirados" => (int)$codigosExpirados['codigos_activacion_expirados'],
                        "tokens_recuperacion_activos" => (int)$tokensRecuperacion['tokens_recuperacion_activos'],
                        "tasa_activacion" => $estadisticasActivacion['total_usuarios'] > 0 ? 
                            round(($estadisticasActivacion['cuentas_activadas'] / $estadisticasActivacion['total_usuarios']) * 100, 2) : 0
                    ],
                    "conteo_por_rol" => array_map(function($item) {
                        return [
                            "id_rol" => (int)$item['id_rol'],
                            "nombre_rol" => $item['nombre_rol'],
                            "total_usuarios" => (int)$item['total_usuarios'],
                            "usuarios_activos" => (int)$item['usuarios_activos']
                        ];
                    }, $conteoPorRol),
                    "filtros_aplicados" => [
                        "solo_activos" => null,
                        "por_rol" => null
                    ],
                    "fecha_consulta" => date('Y-m-d H:i:s')
                ]
            ]
        ];
        
        Flight::json($response, 200);
        
    } catch (Exception $e) {
        $response = [
            "status" => "500 Internal Server Error",
            "body" => [
                "error" => "Error al obtener las estadísticas de usuarios",
                "details" => $e->getMessage()
            ]
        ];
        Flight::json($response, 500);
    }
}
}
