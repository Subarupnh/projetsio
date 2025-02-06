<?php
# Démarre une nouvelle session ou reprend une session existante
session_start();

# Paramètres de connexion à la base de données
$host = 'db';
$dbname = 'login_system';
$username = 'root';
$password = 'root';

try {
    # Crée une nouvelle connexion PDO à la base de données
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    # Définit le mode d'erreur PDO pour lancer des exceptions
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    # Arrête l'exécution du script et affiche un message d'erreur en cas d'échec de connexion
    die("Erreur de connexion à la base de données : " . $e->getMessage());
}

# Détermine l'action actuelle (login par défaut)
$action = $_GET['action'] ?? 'login';
$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    # Démarre la mise en tampon de sortie
    ob_start();
    # Récupère et échappe les valeurs des champs de formulaire
    $inputUsername = htmlspecialchars($_POST['username']);
    $inputPassword = htmlspecialchars($_POST['password']);

    if ($action === 'register') {
        # Récupère et échappe le champ de confirmation du mot de passe
        $confirmPassword = htmlspecialchars($_POST['confirm_password']);
        # Vérifie si les mots de passe correspondent
        if ($inputPassword !== $confirmPassword) {
            $error_message = "Les mots de passe ne correspondent pas.";
        } elseif (!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$/', $inputPassword)) {
            # Vérifie si le mot de passe respecte les règles de complexité
            $error_message = "Le mot de passe doit comporter au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial.";
        } else {
            # Hache le mot de passe
            $hashedPassword = password_hash($inputPassword, PASSWORD_BCRYPT);
            # Prépare la requête SQL pour insérer un nouvel utilisateur
            $query = "INSERT INTO users (username, password, role) VALUES (:username, :password, 'user')";
            $stmt = $pdo->prepare($query);
            # Lie les paramètres à la requête préparée
            $stmt->bindParam(':username', $inputUsername, PDO::PARAM_STR);
            $stmt->bindParam(':password', $hashedPassword, PDO::PARAM_STR);
            # Exécute la requête et redirige vers la page de login en cas de succès
            if ($stmt->execute()) {
                ob_end_clean();
                header("Location: login_register.php?action=login");
                exit();
            } else {
                # Définit un message d'erreur en cas d'échec de l'inscription
                $error_message = "Erreur lors de l'inscription.";
            }
        }
    } elseif ($action === 'login') {
        # Prépare la requête SQL pour sélectionner l'utilisateur par nom d'utilisateur
        $query = "SELECT * FROM users WHERE username = :username";
        $stmt = $pdo->prepare($query);
        # Lie le paramètre à la requête préparée
        $stmt->bindParam(':username', $inputUsername, PDO::PARAM_STR);
        # Exécute la requête
        $stmt->execute();
        # Récupère l'utilisateur correspondant
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            # Vérifie si le compte utilisateur est désactivé
            if (!$user['active']) {
                $error_message = "Votre compte a été désactivé.";
            } elseif (password_verify($inputPassword, $user['password'])) {
                # Vérifie si le mot de passe est correct et initialise la session utilisateur
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                ob_end_clean();
                header("Location: index.php");
                exit();
            } else {
                # Définit un message d'erreur en cas de mot de passe incorrect
                $error_message = "Nom d'utilisateur ou mot de passe incorrect.";
            }
        } else {
            # Définit un message d'erreur en cas de nom d'utilisateur incorrect
            $error_message = "Nom d'utilisateur ou mot de passe incorrect.";
        }
    }
    # Vide le tampon de sortie
    ob_end_clean();
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo ucfirst($action); ?></title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="navbar">
        <div class="links">
            <a href="index.php">Accueil</a>
        </div>
    </div>
    <div class="form-container">
        <h2><?php echo ucfirst($action); ?></h2>
        <?php if ($error_message): ?>
            <div class="error-message"><?php echo $error_message; ?></div>
        <?php endif; ?>
        <form action="login_register.php?action=<?php echo $action; ?>" method="POST">
            <input type="text" name="username" placeholder="Nom d'utilisateur" required>
            <input type="password" name="password" placeholder="Mot de passe" required>
            <?php if ($action === 'register'): ?>
                <input type="password" name="confirm_password" placeholder="Confirmer le mot de passe" required>
            <?php endif; ?>
            <button type="submit"><?php echo ucfirst($action); ?></button>
        </form>
    </div>
</body>
</html>
