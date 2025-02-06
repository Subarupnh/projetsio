<?php
# Démarrer une nouvelle session ou reprendre une session existante
session_start();

# Vérifier si l'utilisateur est connecté
if (!isset($_SESSION['username'])) {
    # Rediriger vers la page de connexion si l'utilisateur n'est pas connecté
    header("Location: login_register.php?action=login");
    exit();
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bienvenue</title>
    <!-- Lien vers le fichier CSS pour le style -->
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="navbar">
        <div class="links">
            <!-- Liens vers l'accueil et la déconnexion -->
            <a href="index.php">Accueil</a>
            <a href="logout.php">Déconnexion</a>
        </div>
    </div>
    <div class="container">
        <div class="content">
            <!-- Afficher un message de bienvenue avec le nom de l'utilisateur -->
            <h1>Bienvenue, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
            <p>Vous êtes maintenant connecté.</p>
            <!-- Afficher un lien vers la page CRUD si l'utilisateur est administrateur -->
            <?php if ($_SESSION['role'] === 'admin'): ?>
                <a href="crud.php" class="btn">Accéder à la page CRUD</a>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
