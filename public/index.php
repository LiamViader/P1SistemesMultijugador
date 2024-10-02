<?php

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
    }
} else if (isset($parameters['register'])) {
    $db = new PDO($db_connection);
    $sqlInsert = 'INSERT INTO users (user_name, user_password) VALUES (:user_name, :user_password)';
    $sqlCheck = 'SELECT * FROM users WHERE user_name = :user_name';

    // verify longitude of password
    $password = $parameters['user_password'];
    $min_length = 8;
    $max_length = 128;
    if (FALSE){// si l'usuari no és un correu

    }
    else{
        $queryCheck = $db->prepare($sqlCheck);
        $queryCheck->bindValue(':user_name', $parameters['user_name']);
        $queryCheck->execute();
        echo "Número de usuarios encontrados: " . $queryCheck->rowCount() . "<br>";
        echo "Buscando usuario: '" . $parameters['user_name'] . "'<br>";
        if (TRUE){ // si l'usuari existeix
            $configuration['{FEEDBACK}'] = '<mark>ERROR: L\'usuari ja existeix. Si us plau, escolliu un altre nom d\'usuari.</mark>';
        }
        else if (strlen($password) < $min_length || strlen($password) > $max_length) {
            // Mostrar missatge error si la contrasenya no cumpleix amb la mida correcta
            $configuration['{FEEDBACK}'] = '<mark>ERROR: La contrasenya ha de tenir entre ' . $min_length . ' i ' . $max_length . ' caràcters</mark>';
        }
        else{
            // HASH PASSWORD
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $query = $db->prepare($sqlInsert);
            $query->bindValue(':user_name', $parameters['user_name']);
            $query->bindValue(':user_password', $hashed_password);
            if ($query->execute()) {
                $configuration['{FEEDBACK}'] = 'Creat el compte <b>' . htmlentities($parameters['user_name']) . '</b>';
                $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar sessió';
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
