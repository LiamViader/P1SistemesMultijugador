<?php
$db_connection = 'sqlite:..\private\users.db';
$db = new PDO($db_connection);

if (isset($_GET['token'])) {
    $token = $_GET['token'];

    // Verificar el token a la base de dades
    $sql = 'SELECT * FROM users WHERE verification_token = :verification_token AND is_verified = 0';
    $query = $db->prepare($sql);
    $query->bindValue(':verification_token', $token);
    $query->execute();

    if ($query->rowCount() > 0) {
        // Marca al usuari com verificat
        $sqlUpdate = 'UPDATE users SET is_verified = 1, verification_token = NULL WHERE verification_token = :verification_token';
        $updateQuery = $db->prepare($sqlUpdate);
        $updateQuery->bindValue(':verification_token', $token);
        $updateQuery->execute();

        echo 'El teu compte ha sigut verificat, inicia sessió.';
    } else {
        echo 'Token de verificació invàlid o ja verificat.';
    }
} else {
    echo 'No sha proporcionat cap token.';
}
?>