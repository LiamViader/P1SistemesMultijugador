<?php
$db_connection = 'sqlite:..\private\users.db';
$db = new PDO($db_connection);


$configuration = array(
    '{FEEDBACK}'          => '',
    '{LOGIN_LOGOUT_TEXT}' => 'Identificar-me',
    '{LOGIN_LOGOUT_URL}'  => '/?page=login',
    '{METHOD}'            => 'GET', // es veuen els paràmetres a l'URL i a la consola (???)
    '{REGISTER_URL}'      => '/?page=register',
    '{SITE_NAME}'         => 'Verificacio correu'
);

if (isset($_GET['token'])) {
    $token = $_GET['token'];

    // Verificar el token
    $sql = 'SELECT * FROM users WHERE verification_token = :verification_token AND is_verified = 0';
    $query = $db->prepare($sql);
    $query->bindValue(':verification_token', $token);
    $query->execute();

    $user = $query->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // Marca al usuari com verificat
        $sqlUpdate = 'UPDATE users SET is_verified = 1, verification_token = NULL WHERE verification_token = :verification_token';
        $updateQuery = $db->prepare($sqlUpdate);
        $updateQuery->bindValue(':verification_token', $token);
        $updateQuery->execute();
        $configuration['{FEEDBACK}'] = "<mark>El teu compte ha sigut verificat, inicia sessió. </mark>";
        $configuration['{LOGIN_USERNAME}'] = $user['user_name'];
        $configuration['{SITE_NAME}'] = "LA MEVA PAGINA";
        $template='login';
    } else {
        $configuration['{FEEDBACK}'] = "<mark>Token de verificació invàlid o ja verificat. </mark>";
        $template='verificationError';
    }
} else {
    $configuration['{FEEDBACK}'] = "<mark>No s\'ha proporcionat cap token. </mark>";
    $template='verificationError';
}
$html = file_get_contents('plantilla_' . $template . '.html', true);
$html = str_replace(array_keys($configuration), array_values($configuration), $html);
echo $html;
?>