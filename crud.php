<?php
# Démarrer une nouvelle session ou reprendre une session existante
session_start();

# Vérifier si l'utilisateur est connecté et a le rôle administrateur, sinon rediriger vers la page d'accueil
if (!isset($_SESSION['username']) || $_SESSION['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

# Paramètres de connexion à la base de données
$host = 'db';
$dbname = 'login_system';
$username = 'root';
$password = 'root';

try {
    # Créer une nouvelle connexion PDO à la base de données
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    # Définir le mode d'erreur PDO pour lancer des exceptions
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    # Arrêter l'exécution du script et afficher un message d'erreur en cas d'échec de connexion
    die("Erreur de connexion à la base de données : " . $e->getMessage());
}

# Nombre d'utilisateurs par page
$items_per_page = 10; 
# Déterminer la page actuelle
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
# Calculer l'offset pour la pagination
$offset = ($page - 1) * $items_per_page;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['deactivate'])) {
        # Désactiver l'utilisateur spécifié
        $id = $_POST['id'];
        $query = "UPDATE users SET active = FALSE WHERE id = :id";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':id', $id);
        $stmt->execute();
    }

    if (isset($_POST['activate'])) {
        # Activer l'utilisateur spécifié
        $id = $_POST['id'];
        $query = "UPDATE users SET active = TRUE WHERE id = :id";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':id', $id);
        $stmt->execute();
    }

    if (isset($_POST['change_password'])) {
        # Changer le mot de passe de l'utilisateur spécifié
        $id = $_POST['id'];
        $new_password = password_hash($_POST['new_password'], PASSWORD_BCRYPT);
        $query = "UPDATE users SET password = :password WHERE id = :id";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':password', $new_password);
        $stmt->bindParam(':id', $id);
        $stmt->execute();
    }

    if (isset($_POST['change_role'])) {
        # Changer le rôle de l'utilisateur spécifié
        $id = $_POST['id'];
        $new_role = $_POST['new_role'];
        $query = "UPDATE users SET role = :role WHERE id = :id";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':role', $new_role);
        $stmt->bindParam(':id', $id);
        $stmt->execute();
    }

    if (isset($_POST['create_user'])) {
        # Créer un nouvel utilisateur
        $username = $_POST['username'];
        $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
        $role = $_POST['role'];
        $query = "INSERT INTO users (username, password, role) VALUES (:username, :password, :role)";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':role', $role);
        $stmt->execute();
    }
}

# Requête pour obtenir le nombre total d'utilisateurs
$total_query = "SELECT COUNT(*) FROM users";
$total_stmt = $pdo->prepare($total_query);
$total_stmt->execute();
$total_users = $total_stmt->fetchColumn();
# Calculer le nombre total de pages pour la pagination
$total_pages = ceil($total_users / $items_per_page);

# Requête pour obtenir les utilisateurs pour la page actuelle
$query = "SELECT * FROM users LIMIT :limit OFFSET :offset";
$stmt = $pdo->prepare($query);
$stmt->bindParam(':limit', $items_per_page, PDO::PARAM_INT);
$stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestion des Utilisateurs</title>
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
        <h1>Gestion des Utilisateurs</h1>

        <!-- Formulaire pour créer un nouvel utilisateur -->
        <div class="form-container">
            <h2>Créer un nouvel utilisateur</h2>
            <form action="crud.php" method="POST">
                <input type="text" name="username" placeholder="Nom d'utilisateur" required>
                <input type="password" name="password" placeholder="Mot de passe" required>
                <select name="role" required>
                    <option value="user">Utilisateur</option>
                    <option value="admin">Administrateur</option>
                </select>
                <button type="submit" name="create_user">Créer l'utilisateur</button>
            </form>
        </div>

        <!-- Tableau des utilisateurs -->
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Nom d'utilisateur</th>
                    <th>Rôle</th>
                    <th>Actif</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $user): ?>
                    <tr>
                        <td data-label="ID"><?php echo htmlspecialchars($user['id']); ?></td>
                        <td data-label="Nom d'utilisateur"><?php echo htmlspecialchars($user['username']); ?></td>
                        <td data-label="Rôle"><?php echo htmlspecialchars($user['role']); ?></td>
                        <td data-label="Actif"><?php echo $user['active'] ? 'Oui' : 'Non'; ?></td>
                        <td data-label="Actions">
                            <!-- Formulaire pour changer le rôle de l'utilisateur -->
                            <form action="crud.php" method="POST" onsubmit="return confirm('Confirmer cette action?');" style="display:inline;">
                                <input type="hidden" name="id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                <select name="new_role">
                                    <option value="user" <?php if ($user['role'] === 'user') echo 'selected'; ?>>Utilisateur</option>
                                    <option value="admin" <?php if ($user['role'] === 'admin') echo 'selected'; ?>>Administrateur</option>
                                </select>
                                <button type="submit" name="change_role">Changer le rôle</button>
                            </form>
                            <?php if ($user['active']): ?>
                                <!-- Formulaire pour désactiver l'utilisateur -->
                                <form action="crud.php" method="POST" onsubmit="return confirm('Confirmer cette action?');" style="display:inline;">
                                    <input type="hidden" name="id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                    <button type="submit" name="deactivate">Désactiver</button>
                                </form>
                            <?php else: ?>
                                <!-- Formulaire pour activer l'utilisateur -->
                                <form action="crud.php" method="POST" onsubmit="return confirm('Confirmer cette action?');" style="display:inline;">
                                    <input type="hidden" name="id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                    <button type="submit" name="activate" style="background-color: red; color: white;">Activer</button>
                                </form>
                            <?php endif; ?>
                            <!-- Formulaire pour changer le mot de passe de l'utilisateur -->
                            <form action="crud.php" method="POST" onsubmit="return confirm('Confirmer cette action?');" style="display:inline;">
                                <input type="hidden" name="id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                <input type="password" name="new_password" placeholder="Nouveau mot de passe" required>
                                <button type="submit" name="change_password">Changer le mot de passe</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <!-- Pagination -->
        <div class="pagination">
            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                <a href="crud.php?page=<?php echo $i; ?>" class="pagination-link"><?php echo $i; ?></a>
            <?php endfor; ?>
        </div>
    </div>
</body>
</html>