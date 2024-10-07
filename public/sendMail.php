<?php
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';
require 'PHPMailer/src/Exception.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;


//compte de gmail: correu: multijugadorsistemes@gmail.com pw: multijugadorsistemes123


function sendVerificationEmail($to, $token) {
    $subject = 'Verifica el teu compte';
    $message = 'Si us plau, verifica el teu compte fent click al següent enllaç: ';
    $message .= 'http://localhost:8000/verifyMail.php?token=' . $token; // Enllaç a la pàgina de verificació amb parametre token corresponent

    $mail = new PHPMailer(true);

    try {
        // Configuracions del servidor smtp
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = 'multijugadorsistemes@gmail.com';
        $mail->Password = 'wjirgwmdglxlytvl'; 
        $mail->SMTPSecure = 'tls';
        $mail->Port = 587;

        // Receptors
        $mail->setFrom('no-reply@tu-sistemesmultijugador.com', 'App Practica 1');
        $mail->addAddress($to); //direccio

        // Contingut del correu
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body    = $message;
        $mail->AltBody = strip_tags($message); 

        $mail->send(); // Envia el correu
        return true;
    } catch (Exception $e) {
        echo 'El correu no sha pogut enviar. Error: ', $mail->ErrorInfo;
        return false; 
    }
}
?>