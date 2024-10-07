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
    '{RECOVERY_URL}'      => '/?page=recovery',
    '{SITE_NAME}'         => 'La meva pàgina',
    '{CURRENT_USER_TEXT}'      => '',
    '{REGISTER_TEXT}'     => 'Registrar-me'
);

$db = new PDO($db_connection);
$current_user = null;


// Función per validar la sessió del usuari
function validateSession($db, &$configuration, &$current_user) {
    if (isset($_COOKIE['session_id'])) {
        $session_id = $_COOKIE['session_id'];
        
        // Consultar si la sesió és valida
        $sql = 'SELECT user_name FROM sessions WHERE session_id = :session_id';
        $query = $db->prepare($sql);
        $query->bindValue(':session_id', $session_id);
        $query->execute();
        $result_row = $query->fetchObject();
    
        if ($result_row) {
            $current_user = $result_row->user_name;
            $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar sessió';
            $configuration['{LOGIN_LOGOUT_URL}'] = '/?page=logout';
            $configuration['{REGISTER_TEXT}'] = '';
            $configuration['{CURRENT_USER_TEXT}'] = 'Sessió iniciada: ' . htmlentities($current_user);
        } else {
            // La sesió no és valida
            setcookie('session_id', '', time() - 3600, "/", "", true, true);
            $configuration['{FEEDBACK}'] = "<mark>ERROR: La sessió s'ha acabat </mark>";
            $current_user = null;
        }
    }
}


// Funció per gestionar el registre de l'usuari
function handleRegister($db, $parameters, &$configuration) {
    $sqlInsert = 'INSERT INTO users (user_name, user_password, verification_token, is_verified) VALUES (:user_name, :user_password, :verification_token, 0)';
    $sqlCheck = 'SELECT user_name FROM users WHERE user_name = :user_name';

    $username = trim($parameters['user_name']);
    $password = trim($parameters['user_password']);
    $confirmation_password = trim($parameters['user_confirm_password']);
    $recaptcha_response = trim($parameters['g-recaptcha-response'] ?? '');

    // Comprovar que les contrasenyes coincideixen
    if ($confirmation_password!=$password) {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: les contrasenyes no coincideixen.</mark>';
        return;
    }

    // Verificar reCAPTCHA
    $recaptcha_secret = '6LcimFUqAAAAAHEbCaUr43uu795ylas3X2umCGRD';
    $recaptcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify';
    $recaptcha = file_get_contents($recaptcha_verify_url . '?secret=' . urlencode($recaptcha_secret) . '&response=' . urlencode($recaptcha_response));
    $recaptcha = json_decode($recaptcha);
    if (!$recaptcha->success) {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: Verificació de reCAPTCHA fallida. Si us plau, intenta-ho de nou.</mark>';
        return;
    }

    // Validar que sigui un correu electrònic
    if (!filter_var($username, FILTER_VALIDATE_EMAIL)) {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: El nom d\'usuari ha de ser una adreça de correu electrònic vàlida.</mark>';
        return;
    }

    // Validar longitud de la contrasenya
    $min_length = 8;
    $max_length = 128;
    if (strlen($password) < $min_length || strlen($password) > $max_length) {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: La contrasenya ha de tenir entre ' . $min_length . ' i ' . $max_length . ' caràcters.</mark>';
        return;
    }

    // Verificar si l'usuari ja existeix
    $queryCheck = $db->prepare($sqlCheck);
    $queryCheck->bindValue(':user_name', $username);
    $queryCheck->execute();
    $result_row = $queryCheck->fetch(PDO::FETCH_ASSOC);
    if ($result_row) {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: L\'usuari ja existeix. Si us plau, escolliu un altre nom d\'usuari.</mark>';
        return;
    }

    // Hash de la contrasenya
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    if ($hashed_password === false) {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: Ha fallat el procés de hashing de la contrasenya.</mark>';
        return;
    }

    // Generar token de verificació
    $token = bin2hex(random_bytes(16));

    //Inserir usuari a la base de dades
    $queryInsert = $db->prepare($sqlInsert);
    $queryInsert->bindValue(':user_name', $username);
    $queryInsert->bindValue(':user_password', $hashed_password);
    $queryInsert->bindValue(':verification_token', $token);
    if ($queryInsert->execute()) {
        // enviar correu de verificació
        if (sendVerificationEmail($username, $token)) {
            $configuration['{FEEDBACK}'] = 'Verifica el correu <b>' . htmlentities($username) . '</b>.';
            $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Iniciar sessió';
        } else {
            $configuration['{FEEDBACK}'] = '<mark>ERROR: No s\'ha pogut enviar el correu de verificació.</mark>';
        }
    } else {
        $configuration['{FEEDBACK}'] = "<mark>ERROR: No s'ha pogut crear el compte <b>" . htmlentities($username) . "</b>.</mark>";
    }
}

// Funció per gestionar l'inici de sessió de l'usuari
function handleLogin($db, $parameters, &$configuration) {
    $sql = 'SELECT * FROM users WHERE user_name = :user_name';
    $query = $db->prepare($sql);
    $query->bindValue(':user_name', $parameters['user_name']);
    $query->execute();
    $result_row = $query->fetch(PDO::FETCH_ASSOC);

    if ($result_row) {
        // Verificar la contrasenya
        if (password_verify($parameters['user_password'], $result_row['user_password'])) {
            if ($result_row['is_verified'] == 1) {
                // Generar ID de sesió
                $session_id = bin2hex(random_bytes(32));
                $sqlInsert = 'INSERT INTO sessions (session_id, user_name, created_at) VALUES (:session_id, :user_name, CURRENT_TIMESTAMP)';
                $queryInsert = $db->prepare($sqlInsert);
                $queryInsert->bindValue(':session_id', $session_id);
                $queryInsert->bindValue(':user_name', $parameters['user_name']);
                $queryInsert->execute();

                // Establecer la cookie de sesió
                setcookie('session_id', $session_id, time() + 86400, "/", "", true, true); // 1 día de duración

                // Actualizar la configuració
                $configuration['{CURRENT_USER_TEXT}'] = '"Sessió" iniciada com <b>' . htmlentities($parameters['user_name']) . '</b>';
                $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar sessió';
                $configuration['{LOGIN_LOGOUT_URL}'] = '/?page=logout';
                $configuration['{REGISTER_TEXT}'] = '';

                // Redirigir a la pàgina d'inici
                header("Location: /?page=home");
                exit;
            } else {
                // Enviar un altre correu de verificació si no està verificat
                if (sendVerificationEmail($result_row['user_name'], $result_row['verification_token'])) {
                    $configuration['{FEEDBACK}'] = '<mark>ERROR: Encara has de verificar el correu. S\'ha tornat a enviar un correu a ' . htmlentities($result_row['user_name']) . '.</mark>';
                } else {
                    $configuration['{FEEDBACK}'] = '<mark>ERROR: Encara has de verificar el correu. S\'ha intentat enviar un correu a ' . htmlentities($result_row['user_name']) . ' però alguna cosa ha anat malament.</mark>';
                }
            }
        } else {
            $configuration['{FEEDBACK}'] = '<mark>ERROR: Usuari desconegut o contrasenya incorrecta.</mark>';
        }
    } else {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: Usuari desconegut o contrasenya incorrecta.</mark>';
    }
}

// Funció per gestionar el tancament de sessió de l'usuari
function handleLogout($db, &$configuration) {
    if (isset($_COOKIE['session_id'])) {
        $session_id = $_COOKIE['session_id'];

        // Eliminar la sessió de la base de dades
        $sql = 'DELETE FROM sessions WHERE session_id = :session_id';
        $query = $db->prepare($sql);
        $query->bindValue(':session_id', $session_id);
        $query->execute();

        // Eliminar la cookie de sessió
        setcookie('session_id', '', time() - 3600, "/", "", true, true);
    }

    // Redirigir a la pàgina de login
    header("Location: /?page=login");
    exit;
}

function handleRecovery($db, $parameters, &$configuration){
    $email = trim($parameters['email']);
    $db = new PDO('sqlite:..\private\users.db');

    // Verificar si l'usuari existeix
    $sqlCheck = 'SELECT user_name FROM users WHERE user_name = :user_name';
    $queryCheck = $db->prepare($sqlCheck);
    $queryCheck->bindValue(':user_name', $email);
    $queryCheck->execute();
    $result_row = $queryCheck->fetch(PDO::FETCH_ASSOC);

    if ($result_row) {
        //generar un token de recuperació
        $token = bin2hex(random_bytes(16));
        $expires = date('Y-m-d H:i:s', strtotime('+1 hour')); // El token expira en 1 hora

        // Emmagatzemar el token i la seva expiració a la base de dades
        $sqlInsertToken = 'INSERT INTO password_reset (user_name, token, expires) VALUES (:user_name, :token, :expires)';
        $queryInsertToken = $db->prepare($sqlInsertToken);
        $queryInsertToken->bindValue(':user_name', $email);
        $queryInsertToken->bindValue(':token', $token);
        $queryInsertToken->bindValue(':expires', $expires);
        $queryInsertToken->execute();

        // Enviar correu electrònic amb el token
        if (sendRecoverEmail($email,$token)) {
            $configuration['{FEEDBACK}'] = '<mark>Un correu electrònic ha estat enviat a ' . $email . ' amb instruccions per restablir la contrasenya.</mark>';
        } else {
            $configuration['{FEEDBACK}'] = '<mark>Error enviant el correu electrònic.</mark>';
        }
    } else {
        $configuration['{FEEDBACK}'] = '<mark>No hi ha cap compte associat a aquest correu electrònic.</mark>';
    }
}



// Validar la sessió de l'usuari
$current_user = null;
validateSession($db, $configuration, $current_user);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $parameters = $_POST;
} else {
    $parameters = $_GET;
}

// rutes i accions
if (isset($parameters['page'])) {
    switch ($parameters['page']) {
        case 'register':
            $template = 'register';
            $configuration['{REGISTER_USERNAME}'] = '';
            $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Ja tinc un compte';
            break;
        case 'login':
            if (!$current_user) {
                $template = 'login';
                $configuration['{LOGIN_USERNAME}'] = '';
            } else {
                $template = 'home';
            }
            break;
        case 'logout':
            handleLogout($db, $configuration);
            break;
        case 'recovery':
            if (!$current_user) {
                $template = 'recuperacio';
                $configuration['{LOGIN_USERNAME}'] = '';
            } else {
                $template = 'home';
            }
            break;
        default:
            $template = 'home';
            break;
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($parameters['register'])) {
        handleRegister($db, $parameters, $configuration);
    } elseif (isset($parameters['login'])) {
        handleLogin($db, $parameters, $configuration);
    } elseif(isset($parameters['recuperacio'])){
        $template = 'recuperacio';
        handleRecovery($db, $parameters, $configuration);
    }
}

// Mostrar la plantilla corresponent
$template_file = 'plantilla_' . $template . '.html';
$html = file_get_contents($template_file,true);
$html = str_replace(array_keys($configuration), array_values($configuration), $html);
echo $html;

?>