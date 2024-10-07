<?php

require 'sendMail.php';

$configuration = array(
    '{FEEDBACK}'          => '',
    '{LOGIN_USERNAME}'    => '',
    '{LOGIN_LOGOUT_TEXT}' => 'Identificar-me',
    '{LOGIN_LOGOUT_URL}'  => '/?page=login',
    '{RECOVERY_URL}'      => '/?page=recovery',
    '{REGISTER_URL}'      => '/?page=register',
    '{SITE_NAME}'         => 'Reset',
    '{METHOD}'            => 'POST',
    
);
$template='reset_password';

if (isset($_GET['token'])) {
    $token = $_GET['token'];
    //  validar el token
    $db = new PDO('sqlite:..\private\users.db');
    $sqlValidateToken = 'SELECT user_name FROM password_reset WHERE token = :token AND expires > DATETIME("now")';
    $queryValidate = $db->prepare($sqlValidateToken);
    $queryValidate->bindValue(':token', $token);
    $queryValidate->execute();
    $result_row = $queryValidate->fetch(PDO::FETCH_ASSOC);

    if ($result_row) {
        if (isset($_POST['reset_password'])) {
            $new_password = trim($_POST['new_password']);
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

            // Actualitzar la contrasenya a la base de dades
            $sqlUpdatePassword = 'UPDATE users SET user_password = :password WHERE user_name = :user_name';
            $queryUpdate = $db->prepare($sqlUpdatePassword);
            $queryUpdate->bindValue(':password', $hashed_password);
            $queryUpdate->bindValue(':user_name', $result_row['user_name']);
            $queryUpdate->execute();

            // Eliminar el token de la base de dades
            $sqlDeleteToken = 'DELETE FROM password_reset WHERE token = :token';
            $queryDelete = $db->prepare($sqlDeleteToken);
            $queryDelete->bindValue(':token', $token);
            $queryDelete->execute();

            $configuration['{FEEDBACK}'] = "<mark>La teva contrasenya ha estat restablerta amb èxit. </mark>";
            $template='login';
        }
    } else {
        $configuration['{FEEDBACK}'] = "<mark>El token és invàlid o ha expirat.</mark>";
    }
}
$html = file_get_contents('plantilla_' . $template . '.html', true);
$html = str_replace(array_keys($configuration), array_values($configuration), $html);
echo $html;
?>