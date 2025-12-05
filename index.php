<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
require 'vendor/autoload.php';
// si no estás utilizando Composer, carga el framework directamente
// require 'flight/Flight.php';
require 'classes/Users.php';

// Las variables de entorno estarán disponibles vía $_ENV o getenv()
// En Render.com las variables deben estar configuradas directamente
if (file_exists(__DIR__.'/.env')) {
    // Solo cargar .env si el archivo existe (para desarrollo local)
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
    $dotenv->load();
}

date_default_timezone_set($_ENV['PHP_DEFAULT_TIMEZONE']);

$users = new Users();

function get_user_ip() {
    $ip = 'unknown';
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } elseif (isset($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    // Si hay múltiples IPs (por proxies), toma la primera
    if (strpos($ip, ',') !== false) {
        $ip = explode(',', $ip)[0];
    }
    return trim($ip);
}

// Función para establecer los encabezados de CORS
function setCorsHeaders(){
    header('Access-Control-Allow-Origin: '.$_ENV['URL_FRONTEND']);
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
}

// Aplica los encabezados CORS en todas las solicitudes
Flight::before('start', function(){
    setCorsHeaders();
});

// Establecer los encabezados OPTIONS para los CORS y se guarden en cache del navegador 1 día
Flight::route('OPTIONS /*', function(){
    setCorsHeaders();
    header('Access-Control-Max-Age: 86400'); // 1 día en segundos
    http_response_code(200);
    exit();
});

// Luego define una ruta y asigna una función para manejar la solicitud.
Flight::route('/'.$_ENV['API_VERSION_URL'], function(){
  $array = [
    "status" => "200 ok",
    "body" => ["data" => [
        "texto" => "Hola mundo desde Flight!",
    ]]];
  echo json_encode($array);
});

// Endpoint que reliza la autenticacion del usuario para obtener un token
Flight::route('POST /'.$_ENV['API_VERSION_URL'].'/auth', function(){
    
    
    // 1. Definir constantes de seguridad
    define('MAX_LOGIN_ATTEMPTS', 3);
    define('BLOCK_MINUTES', 2);

    // 2. Conexión a la BD y obtener IP
    $db = Flight::db();
    $ip = get_user_ip(); 

    // 3. Revisar si la IP ya está bloqueada
    $query_ip = $db->prepare("SELECT failed_attempts, blocked_until FROM login_attempts WHERE ip_address = :ip");
    $query_ip->execute([':ip' => $ip]);
    $attempt = $query_ip->fetch();

    $now = new DateTime();
    
    if ($attempt && $attempt['blocked_until']) {
        $blocked_time = new DateTime($attempt['blocked_until']);

        if ($now < $blocked_time) {
            // AÚN ESTÁ BLOQUEADO
            $remaining = $now->diff($blocked_time);
            $remaining_str = $remaining->format('%i minutos y %s segundos');
            
            $response = [
                "status" => "429 Too Many Requests", // Código HTTP para rate limiting
                "body" => ["data" => [
                    "message" => "Acceso bloqueado. Intente de nuevo en $remaining_str."
                ]]
            ];
            Flight::json($response, 429);
            return;
        } else {
            // El bloqueo expiró, limpiar el registro para permitir un nuevo intento
            $db->prepare("DELETE FROM login_attempts WHERE ip_address = :ip")->execute([':ip' => $ip]);
            $attempt = null; // Limpiamos el intento para que cuente desde cero
        }
    }

    // Función 'helper' para manejar fallos de login
    $handle_failure = function($default_message = "No se puede validar su identidad, por favor intente de nuevo") use ($db, $ip, $attempt) {
        
        $current_attempts = ($attempt) ? (int)$attempt['failed_attempts'] : 0;
        $new_attempts = $current_attempts + 1;
        $message = $default_message;

        if ($new_attempts >= MAX_LOGIN_ATTEMPTS) {
            // Bloquear al usuario
            $block_until_time = (new DateTime())->add(new DateInterval("PT" . BLOCK_MINUTES . "M"));
            $block_until_str = $block_until_time->format('Y-m-d H:i:s');
            
            $db->prepare("
                INSERT INTO login_attempts (ip_address, failed_attempts, blocked_until) 
                VALUES (:ip, :attempts, :blocked_until) 
                ON CONFLICT (ip_address) DO UPDATE 
                SET failed_attempts = :attempts, blocked_until = :blocked_until
            ")->execute([
                ':ip' => $ip,
                ':attempts' => $new_attempts,
                ':blocked_until' => $block_until_str
            ]);
            
            $message = "Ha excedido el número de intentos de inicio de sesión. Su acceso está bloqueado por " . BLOCK_MINUTES . " minutos.";
        } else {
            // Solo incrementar el contador
            $db->prepare("
                INSERT INTO login_attempts (ip_address, failed_attempts, blocked_until) 
                VALUES (:ip, :attempts, NULL) 
                ON CONFLICT (ip_address) DO UPDATE 
                SET failed_attempts = :attempts, blocked_until = NULL
            ")->execute([
                ':ip' => $ip,
                ':attempts' => $new_attempts
            ]);
        }
        
        $response = [
            "status" => "401 Unauthorized",
            "body" => ["data" => ["message" => $message]]
        ];
        Flight::json($response, 401);
    };


    // Lógica de login existente
    $user_input = Flight::request()->data->user;
    $password = Flight::request()->data->password;

    // Preparar y ejecutar la consulta
    $query = $db->prepare("SELECT 
        usuario.id_usuario, 
        usuario.nombre_usuario, 
        usuario.password, 
        usuario.cuenta_activa,
        rol.nombre_rol, 
        rol.id_rol
    FROM usuario 
    JOIN usuario_rol ON usuario.id_usuario = usuario_rol.fk_id_usuario
    JOIN rol ON usuario_rol.fk_id_rol = rol.id_rol
    WHERE usuario.nombre_usuario = :user AND usuario.activo = true");
    $query->execute([":user" => $user_input]);

    // Verificar si se encontró almenos un registro
    if($query->rowCount() > 0){

        $user = $query->fetch();

        // Verificar si la cuenta está activa
        if (!$user['cuenta_activa']) {
            // MODIFICADO: Llamar al helper de fallo
            $handle_failure("Su cuenta se encuentra inactiva. Activela siguiendo las instrucciones que recibio a su correo");
            return;
        }

        // Verificar la contraseña
        if (password_verify($password, $user['password'])) {
            
            // --- NUEVO: Limpiar intentos en caso de éxito ---
            if ($attempt) {
                $db->prepare("DELETE FROM login_attempts WHERE ip_address = :ip")->execute([':ip' => $ip]);
            }

            // Generación del token JWT
            $now = strtotime("now");
            $key = $_ENV['API_KEY'];
            $payload = [
                'exp' => $now + 3600,
                'data' => ["user" => [
                    "id_rol" => $user['id_rol'],
                    "id_usuario" => $user['id_usuario'],
                    "nombre_rol" => $user['nombre_rol']
                ]]
            ];
            $jwt = JWT::encode($payload, $key, 'HS256');

            // Respuesta en caso de éxito
            $response = [
                "status" => "200 OK",
                "body" => ["data" => [
                    "token" => $jwt,
                    "user" => [
                        "id_rol" => $user['id_rol'],
                        "nombre_usuario" => $user['nombre_usuario'],
                        "id_usuario" => $user['id_usuario'],
                        "nombre_rol" => $user['nombre_rol']
                    ]
                ]]
            ];
            Flight::json($response, 200);
        } else {
            // MODIFICADO: Contraseña incorrecta, llamar al helper de fallo
            $handle_failure();
        }
    } else {
        // MODIFICADO: Usuario no encontrado, llamar al helper de fallo
        $handle_failure();
    }
});


// Obtener el token de las peticiones
function getToken(){
    try{
        // MÚLTIPLES MÉTODOS para obtener el header Authorization
        $authorization = '';
        
        // Método 1: Apache headers (funciona en web)
        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $authorization = $headers["Authorization"] ?? $headers["authorization"] ?? "";
        }
        
        // Método 2: $_SERVER (funciona en Android/React Native)
        if (empty($authorization) && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authorization = $_SERVER['HTTP_AUTHORIZATION'];
        }
        
        // Método 3: Headers con prefijo REDIRECT_ 
        if (empty($authorization) && isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $authorization = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }
        
        // Método 4: Buscar manualmente en todos los headers
        if (empty($authorization)) {
            foreach ($_SERVER as $key => $value) {
                if (strpos($key, 'HTTP_') === 0 && strtoupper($key) === 'HTTP_AUTHORIZATION') {
                    $authorization = $value;
                    break;
                }
            }
        }

        // Verificamos que el encabezado Authorization esté presente
        if(empty($authorization)){
            error_log("Encabezado de autorización no presente o vacío");
            return null;
        }
        
        $authorizationArray = explode(" ", $authorization);

        // Verificamos que el token esté en el formato correcto
        if(count($authorizationArray) < 2 || empty($authorizationArray[1])){
            error_log("Formato de token inválido en el encabezado de autorización: " . $authorization);
            return null;
        }

        $token = $authorizationArray[1];
        $key = $_ENV['API_KEY'];

        // Decodificamos el token
        $decodedToken = JWT::decode($token, new Key($key, 'HS256'));
        return $decodedToken;
    }catch(Exception $e){
        // Manejo de errores: registramos o mostramos el mensaje de error y retornamos null
        error_log("Error al obtener el token: " . $e->getMessage());
        return null;
    }
}

if (!function_exists('apache_request_headers')) {
    function apache_request_headers() {
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (substr($key, 0, 5) == 'HTTP_') {
                $header = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                $headers[$header] = $value;
            }
        }
        return $headers;
    }
}

// Validar el token
function validateToken(){

    $info = getToken();

    //Obtenemos la información encriptada del token
    $exp = $info?->exp;
    $id_usuario = $info?->data?->user?->id_usuario;
    $nombre_rol = $info?->data?->user?->nombre_rol;
    $id_rol = $info?->data?->user?->id_rol;

    if($id_usuario !== null && $nombre_rol !== null && $id_rol !== null){
        // Conexión a la BD
        $db = Flight::db();

        // Preparar y ejecutar la consulta
        $query = $db->prepare("SELECT usuario.id_usuario 
             FROM usuario 
             JOIN usuario_rol ON usuario.id_usuario = usuario_rol.fk_id_usuario
             JOIN rol ON usuario_rol.fk_id_rol = rol.id_rol
             WHERE usuario.id_usuario = :id AND rol.nombre_rol = :rol AND rol.id_rol = :id_rol");
        $query->execute([
            ":id" => $id_usuario,
            ":id_rol" => $id_rol,
            ":rol" => $nombre_rol
        ]);

        // Obtenemos el resultado de la consulta
        $result = $query->fetchColumn();
        return ["exp" => $exp, $result];
        
    }
    return null;
}

// Endpoint que verifica el token
Flight::route('GET /'.$_ENV['API_VERSION_URL'].'/auth/token/validation', function(){
    try {
        // Obtener el token
        $tokenInfo = validateToken();

        // Verificar si el token es nulo
        if ($tokenInfo === null) {
            $response = [
                "status" => "401 Unauthorized",
                "body" => ["data" => [
                    "message" => "Token inválido o no autorizado"
                ]]
            ];
            Flight::json($response, 401);
            return;
        }

        // Obtener el token sin el prefijo "Bearer" desde los headers
        $headers = apache_request_headers();
        $authorization = $headers["Authorization"] ?? "";
        $token = str_replace("Bearer ", "", $authorization);

        // Verificar conexión a la base de datos
        $db = Flight::db();

        // Comprobar si el token está en la lista negra
        $checkQuery = $db->prepare("SELECT COUNT(*) FROM lista_negra WHERE token_invalido = :token");
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

        // Si el token no está en la lista negra, proceder con la validación normal
        $currentTime = time();
        $secondsRemaining = $tokenInfo['exp'] - $currentTime;

        // Respuesta en caso de token válido
        $response = [
            "status" => "200 OK",
            "body" => ["data" => [
                "message" => "Token válido",
                "seconds_remaining" => max(0, $secondsRemaining)
            ]]
        ];
        Flight::json($response, 200);

    } catch (Exception $e) {
        // Manejo de cualquier otra excepción no capturada
        $response = [
            "status" => "401 Unauthorized",
            "body" => ["data" => [
                "message" => "Error en la validación del token"
            ]]
        ];
        Flight::json($response, 401);
    }
});

// Endpoint que invalida un token
Flight::route('POST /'.$_ENV['API_VERSION_URL'].'/auth/token/revoke', function(){
    try{

        // DEBUG: Log todos los headers recibidos
        error_log("=== HEADERS RECIBIDOS ===");
        error_log("SERVER headers: " . print_r($_SERVER, true));

        // LUEGO: Obtener el token decodificado
        $decodedToken = validateToken();

        // Verificar si el token no es válido
        if(!$decodedToken){
            throw new Exception("Token inválido o no autorizado", 401); // Responder con 401 Unauthorized
        }

        // PRIMERO: Obtener el token sin el prefijo "Bearer" directamente desde los headers
        $headers = getallheaders();
        $authorization = '';
        foreach ($headers as $key => $value) {
            if (strtolower($key) === 'authorization') {
                $authorization = $value;
                break;
            }
        }
        $token = str_replace("Bearer ", "", $authorization);
        
        // Verificar si se obtuvo el token
        if (empty($token)) {
            throw new Exception("Token no proporcionado en los headers", 401);
        }



        // Verificar conexión a la base de datos
        $db = Flight::db();

        // Comprobar si el token ya está en la lista negra
        $checkQuery = $db->prepare("SELECT COUNT(*) FROM lista_negra WHERE token_invalido = :token");
        $checkQuery->execute([":token" => $token]);
        $isBlacklisted = $checkQuery->fetchColumn();

        if($isBlacklisted > 0){
            // Respuesta en caso de que el token ya esté invalidado
            $response = [
                "status" => "200 OK",
                "body" => ["data" => [
                    "message" => "El token ya se encuentra en la lista negra.",
                ]]
            ];
            Flight::json($response, 200);
            return;
        }

        $formattedExpirationDate = date('Y-m-d H:i:s', $decodedToken['exp']);

        // Insertar el token en la lista negra
        $insertQuery = $db->prepare("INSERT INTO lista_negra (token_invalido, fecha, fecha_expiracion) VALUES (:token, NOW(), :fecha_expiracion)");
        $insertQuery->execute([":token" => $token, ":fecha_expiracion" => $formattedExpirationDate]);

        // Verificar si la inserción fue exitosa
        if($insertQuery->rowCount() > 0){
            // Respuesta en caso de éxito
            $response = [
                "status" => "200 OK",
                "body" => ["data" => [
                    "message" => "Token agregado a la lista negra exitosamente.",
                ]]
            ];
            Flight::json($response, 200);
        }else{
            throw new Exception("No se pudo insertar el token en la lista negra.", 500);
        }
    }catch(Exception $e){
        $statusCode = $e->getCode() == 401 ? 401 : 500;
        $response = [
            "status" => $statusCode == 401 ? "401 Unauthorized" : "500 Internal Server Error",
            "body" => ["data" => [
                "message" => $e->getMessage(),
            ]]
        ];
        Flight::json($response, $statusCode);
    }
});

// USUARIOS
// Endpoint que obtiene el correo del usuario
Flight::route('GET /'.$_ENV['API_VERSION_URL'].'/users/correo/@id_usuario', [$users, 'getCorreoUsuario']);

// Endpoint para registrar usuarios sin uso del token
Flight::route('POST /'.$_ENV['API_VERSION_URL'].'/users/register',[$users, 'registerUSer']);

// Endpoint que envia el codigo de activacion por correo
Flight::route('POST /'.$_ENV['API_VERSION_URL'].'/auth/send-activation-code/@id_usuario', [$users, 'sendActivationCode']);

// Endpoint que activa la cuenta del usuario ingresando un codigo que llega a su correo
Flight::route('POST /'.$_ENV['API_VERSION_URL'].'/auth/activate-account/@id_usuario',[$users, 'activateAccount']);

// Endpoint para reenviar el codigo de activacion de la cuenta
Flight::route('POST /'.$_ENV['API_VERSION_URL'].'/auth/resend-activation-code/@id_usuario', [$users, 'resendActivationCodeById']);

// Endpoint que crea un usuario validando el token
Flight::route('POST /'.$_ENV['API_VERSION_URL'].'/users/create',[$users, 'createUser']);

// Endpoint que desactiva un usuario por su id validando el token
Flight::route('PUT /'.$_ENV['API_VERSION_URL'].'/users/@id_usuario/disable',[$users, 'disableUserById']);

// Endpoint que edita la contraseña de un usuario por su id
Flight::route('PUT /'.$_ENV['API_VERSION_URL'].'/users/@id_usuario/password',[$users, 'editUserPasswordById']);

// Endpoint que obtiene la lista de los usuarios validando el token pero solo los que tienen el activo = true
Flight::route('GET /'.$_ENV['API_VERSION_URL'].'/users/active', [$users, 'getAllActiveUsers']);

// Endpoint que cuenta el número de usuarios registrados validando el token
Flight::route('GET /'.$_ENV['API_VERSION_URL'].'/users/count', [$users, 'getCountAllUsers']);

// Endpoint que edita un usuario por su id
Flight::route('PUT /'.$_ENV['API_VERSION_URL'].'/users/@id_usuario',[$users, 'editUserById']);

// Endpoint que obtiene la lista de los usuarios validando el token
Flight::route('GET /'.$_ENV['API_VERSION_URL'].'/users', [$users, 'getAllUsers']);

// Endpoint que cuenta el número de usuarios activos
Flight::route('GET /'.$_ENV['API_VERSION_URL'].'/users/active/count', [$users, 'getCountAllActiveUsers']);

// Endpoint que cuenta el numero de secretarias activas
Flight::route('GET /'.$_ENV['API_VERSION_URL'].'/secretaries/active/count', [$users, 'getCountAllActiveSecretaries']);

// ENDPOINTS PARA CAMBIAR LA CONTRASEÑA DEL USUARIO MEDIANTE CORREO

// Endpoint que solicita la recuperacion de contraseña y recibe el correo
Flight::route('POST /'.$_ENV['API_VERSION_URL'].'/users/solicitar-recuperacion', [$users, 'solicitarRecuperacion']);

// Endpoint que restablece la contraseña
Flight::route('POST /'.$_ENV['API_VERSION_URL'].'/users/restablecer-password', [$users, 'restablecerPasswordPorToken']);

// Finalmente, inicia el framework.
Flight::start();

?>