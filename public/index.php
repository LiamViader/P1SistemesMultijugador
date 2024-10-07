<?php

require 'sendMail.php';

// defaults
$template = 'home';
$db_connection = 'sqlite:..\private\users.db';
$configuration = array(
    '{FEEDBACK}'          => '',
    '{LOGIN_LOGOUT_TEXT}' => 'Identificar-me',
    '{LOGIN_LOGOUT_URL}'  => '/?page=login',
    '{METHOD}'            => 'POST', // es veuen els paràmetres a l'URL i a la consola (???)
    '{REGISTER_URL}'      => '/?page=register',
    '{SITE_NAME}'         => 'La meva pàgina',
    '{CURRENT_USER_TEXT}'      => '',
    '{REGISTER_TEXT}'     => 'Registrar-me'
);

$db = new PDO($db_connection);
$current_user = null;
if (isset($_COOKIE['session_id'])) { // Verificar si hi ha cookie de sessió
    $session_id = $_COOKIE['session_id'];

    // Consultar si la sessió es valida
    $sql = 'SELECT user_name FROM sessions WHERE session_id = :session_id';
    $query = $db->prepare($sql);
    $query->bindValue(':session_id', $session_id);
    $query->execute();
    $result_row = $query->fetchObject();

    if ($result_row) {
        $current_user = $result_row->user_name; // Almacena el nombre del usuario actual
        $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar sessió';
        $configuration['{LOGIN_LOGOUT_URL}'] = '/?page=logout';
        $configuration['{REGISTER_TEXT}'] = '';
        $configuration['{CURRENT_USER_TEXT}'] = 'Sessió iniciada: ' . htmlentities($current_user);
    } else {
        // La sesión no es válida
        unset($_COOKIE['session_id']); // Eliminar la cookie
        setcookie('session_id', '', time() - 3600, "/", "", true, true);
        // Redirigir o mostrar un mensaje de error
        $configuration['{FEEDBACK}'] = "<mark>ERROR: La sessió s'ha acabat </mark>";
        $current_user = null;
    }
}

// parameter processing
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $parameters = $_POST;
}
else if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $parameters = $_GET;
}

if (isset($parameters['page'])) {
    if ($parameters['page'] == 'register') {
        $template = 'register';
        $configuration['{REGISTER_USERNAME}'] = '';
        $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Ja tinc un compte';
    } else if ($parameters['page'] == 'login' && !$current_user) { // si login i sessio no iniciada
        $template = 'login';
        $configuration['{LOGIN_USERNAME}'] = '';
    } else if($parameters['page'] == 'login'){ // si login i la sessió ja està iniciada
        $template = 'home';
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
    
    $recaptcha_secret = '6LcimFUqAAAAAHEbCaUr43uu795ylas3X2umCGRD';
    $recaptcha_response = $parameters['g-recaptcha-response'];

    $recaptcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify?';
    $recaptcha = file_get_contents($recaptcha_verify_url . '?secret=' . $recaptcha_secret . '&response=' . $recaptcha_response);
    $recaptcha = json_decode($recaptcha);
    if (!$recaptcha->success) {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: Verificació de reCAPTCHA fallida. Si us plau, intenta-ho de nou'. $recaptcha_response . '</mark>';
        $min_length = 8;
        $max_length = 128;
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
            else if (strlen($password) < $min_length || strlen($password) > $max_length) {
                // Mostrar missatge error si la contrasenya no cumpleix amb la mida correcta
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
                        $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Iniciar sessió';
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
    } else {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: Verificació de reCAPTCHA fallida. Si us plau, intenta-ho de nou.</mark>';
    }
    // to verify longitude of password
    
} else if (isset($parameters['login'])) {
    $db = new PDO($db_connection);
    $sql = 'SELECT * FROM users WHERE user_name = :user_name';
    $query = $db->prepare($sql);
    $query->bindValue(':user_name', $parameters['user_name']);
    $query->execute();
    $result_row = $query->fetch(PDO::FETCH_ASSOC);

    if ($result_row) {
        list($user_salt, $user_hash) = explode(':', $result_row['user_password']); //separar sal i hash
        $input_hashed_password = hash_pbkdf2('sha256', $parameters['user_password'], $user_salt, 10000, 64); //tornar a fer hash
        if ($input_hashed_password === $user_hash){ //comprovar hash si son iguals
            if($result_row['is_verified']==1){//si ja ha verificat el correu
                $session_id = bin2hex(random_bytes(32)); //generar id de la sessió
                $sql = 'INSERT INTO sessions (session_id, user_name, created_at) VALUES (:session_id, :user_name, CURRENT_TIMESTAMP)';
                $query = $db->prepare($sql);
                $query->bindValue(':session_id', $session_id);
                $query->bindValue(':user_name', $parameters['user_name']);
                $query->execute();

                setcookie('session_id', $session_id, time() + (86400), "/", "", true, true); // 1 dia de duració

                $configuration['{CURRENT_USER_TEXT}'] = '"Sessió" iniciada com <b>' . htmlentities($parameters['user_name']) . '</b>';
                $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar sessió';
                $configuration['{LOGIN_LOGOUT_URL}'] = '/?page=logout';
                $configuration['{REGISTER_TEXT}'] = '';
            }
            else{ // si correu no verificat
                if (sendVerificationEmail($result_row['user_name'], $result_row['verification_token'])) { //enviar un altre correu de correu de verificació
                    $configuration['{FEEDBACK}'] = '<mark>ERROR: Encara sha de verificar el correu. sha tornat a enviar un correu a ' . $result_row['user_name'] . '</mark>';
                } else {
                    $configuration['{FEEDBACK}'] = '<mark>ERROR: Encara sha de verificar el correu. sha intentat enviar un correu a ' . $result_row['user_name'] . ' pero algo ha anat malament</mark>';
                }
            }

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
