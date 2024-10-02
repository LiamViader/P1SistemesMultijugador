<?php

require 'sendMail.php';

// defaults
$template = 'home';
$db_connection = 'sqlite:..\private\users.db';
$configuration = array(
    '{FEEDBACK}'          => '',
    '{LOGIN_LOGOUT_TEXT}' => 'Identificar-me',
    '{LOGIN_LOGOUT_URL}'  => '/?page=login',
    '{METHOD}'            => 'GET', // es veuen els paràmetres a l'URL i a la consola (???)
    '{REGISTER_URL}'      => '/?page=register',
    '{SITE_NAME}'         => 'La meva pàgina'
);

$db = new PDO($db_connection);

if (isset($_COOKIE['session_id'])) { // Verificar si hi ha cookie de sessió
    $session_id = $_COOKIE['session_id'];

    // Consultar si la sessió es valida
    $sql = 'SELECT user_name FROM sessions WHERE session_id = :session_id';
    $query = $db->prepare($sql);
    $query->bindValue(':session_id', $session_id);
    $query->execute();
    $result_row = $query->fetchObject();

    if ($result_row) {
        // La sesión es válida
        $current_user = $result_row->user_name; // Almacena el nombre del usuario actual
    } else {
        // La sesión no es válida
        unset($_COOKIE['session_id']); // Eliminar la cookie
        setcookie('session_id', '', time() - 3600, "/", "", true, true);
        // Redirigir o mostrar un mensaje de error
        $configuration['{FEEDBACK}'] = "<mark>ERROR: La sessió s'ha acabat </mark>";
    }
}

// parameter processing
$parameters = $_GET;
if (isset($parameters['page'])) {
    if ($parameters['page'] == 'register') {
        $template = 'register';
        $configuration['{REGISTER_USERNAME}'] = '';
        $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Ja tinc un compte';
    } else if ($parameters['page'] == 'login') {
        $template = 'login';
        $configuration['{LOGIN_USERNAME}'] = '';
    } else if ($parameters['page'] == 'logout'){
        $session_id = $_COOKIE['session_id'];
        $sql = 'DELETE FROM sessions WHERE session_id = :session_id';
        $query = $db->prepare($sql);
        $query->bindValue(':session_id', $session_id);
        $query->execute();

        unset($_COOKIE['session_id']);
        setcookie('session_id', '', time() - 3600, "/", "", true, true);

        header("Location: /?page=login");
        exit;
    }
} else if (isset($parameters['register'])) {
    $db = new PDO($db_connection);
    $sqlInsert = 'INSERT INTO users (user_name, user_password, verification_token, is_verified) VALUES (:user_name, :user_password, :verification_token, 0)';
    $sqlCheck = 'SELECT user_name FROM users WHERE user_name = :user_name';


    $username = $parameters['user_name'];
    $password = $parameters['user_password'];

    if (!filter_var($username, FILTER_VALIDATE_EMAIL)) {
        // Si l'usuari no és un correu electrònic vàlid
        $configuration['{FEEDBACK}'] = '<mark>ERROR: El nom d\'usuari ha de ser una adreça de correu electrònic vàlida.</mark>';
        $crearUsuari = false;
    }
    else{
        $queryCheck = $db->prepare($sqlCheck);
        $username=$parameters['user_name'];
        $queryCheck->bindValue(':user_name', $username);
        $queryCheck->execute();
        $result_row = $queryCheck->fetch(PDO::FETCH_ASSOC);
        if ($result_row){ // si l'usuari existeix
            $configuration['{FEEDBACK}'] = '<mark>ERROR: L\'usuari ja existeix. Si us plau, escolliu un altre nom d\'usuari.</mark>';
        }
        else if (strlen($password) < $min_length || strlen($password) > $max_length) {    // verify longitude of password
            // Mostrar missatge error si la contrasenya no cumpleix amb la mida correcta
            $min_length = 8;
            $max_length = 128;
            $configuration['{FEEDBACK}'] = '<mark>ERROR: La contrasenya ha de tenir entre ' . $min_length . ' i ' . $max_length . ' caràcters</mark>';
        }
        else{
            // HASH PASSWORD
            $salt = bin2hex(random_bytes(16)); // crear sal aleatoria
            $hashed_password = hash_pbkdf2('sha256', $password, $salt, 10000, 64); //fer hash

            $password_final = $salt . ':' . $hashed_password; // ajuntar amb el format 'sal:hash'

            $token = bin2hex(random_bytes(16)); // Genera un token aleatori per verificar a partir del correu

            $query = $db->prepare($sqlInsert);
            $query->bindValue(':user_name', $parameters['user_name']);
            $query->bindValue(':user_password', $password_final);
            $query->bindValue(':verification_token', $token);
            if ($query->execute()) {
                if (sendVerificationEmail($parameters['user_name'], $token)) { //enviar correu de verificació
                    $configuration['{FEEDBACK}'] = 'Verifica el correu <b>' . htmlentities($parameters['user_name']) . '</b>';
                    $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar sessió';
                } else {
                    $configuration['{FEEDBACK}'] = '<mark>ERROR: No s\'ha pogut enviar el correu de verificació.</mark>';
                }
            } else {
                // Això no s'executarà mai (???)
                $configuration['{FEEDBACK}'] = "<mark>ERROR: No s'ha pogut crear el compte <b>"
                    . htmlentities($parameters['user_name']) . '</b></mark>';
            }
        }
    }
} else if (isset($parameters['login'])) {
    $db = new PDO($db_connection);
    $sql = 'SELECT user_password FROM users WHERE user_name = :user_name';
    $query = $db->prepare($sql);
    $query->bindValue(':user_name', $parameters['user_name']);
    $query->execute();
    $result_row = $query->fetchObject();

    if ($result_row) {
        list($user_salt, $user_hash) = explode(':', $result_row->user_password); //separar sal i hash
        $input_hashed_password = hash_pbkdf2('sha256', $parameters['user_password'], $user_salt, 10000, 64); //tornar a fer hash
        if ($input_hashed_password === $user_hash){ //comprovar hash si son iguals
            $session_id = bin2hex(random_bytes(32)); //generar id de la sessió
            $sql = 'INSERT INTO sessions (session_id, user_name, created_at) VALUES (:session_id, :user_name, CURRENT_TIMESTAMP)';
            $query = $db->prepare($sql);
            $query->bindValue(':session_id', $session_id);
            $query->bindValue(':user_name', $parameters['user_name']);
            $query->execute();

            setcookie('session_id', $session_id, time() + (86400), "/", "", true, true); // 1 dia de duració

            $configuration['{FEEDBACK}'] = '"Sessió" iniciada com <b>' . htmlentities($parameters['user_name']) . '</b>';
            $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar "sessió"';
            $configuration['{LOGIN_LOGOUT_URL}'] = '/?page=logout';
        } else {
            $configuration['{FEEDBACK}'] = '<mark>ERROR: Usuari desconegut o contrasenya incorrecta</mark>';
        }
        
    } else {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: Usuari desconegut o contrasenya incorrecta</mark>';
    }
}
// process template and show output
$html = file_get_contents('plantilla_' . $template . '.html', true);
$html = str_replace(array_keys($configuration), array_values($configuration), $html);
echo $html;
