<?php
session_start();

if (!isset($_SESSION['username']) || $_SESSION['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

$host = 'db';
$dbname = 'login_system';
$username = 'root';
$password = 'root';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Erreur de connexion à la base de données : " . $e->getMessage());
}

$items_per_page = 3;
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$offset = ($page - 1) * $items_per_page;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['deactivate'])) {
        $id = $_POST['id'];
        $query = "UPDATE users SET active = FALSE WHERE id = :id";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':id', $id);
        $stmt->execute();
    }

    if (isset($_POST['activate'])) {
        $id = $_POST['id'];
        $query = "UPDATE users SET active = TRUE WHERE id = :id";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':id', $id);
        $stmt->execute();
    }

    if (isset($_POST['change_password'])) {
        $id = $_POST['id'];
        $new_password = password_hash($_POST['new_password'], PASSWORD_BCRYPT);
        $query = "UPDATE users SET password = :password WHERE id = :id";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':password', $new_password);
        $stmt->bindParam(':id', $id);
        $stmt->execute();
    }

    if (isset($_POST['change_role'])) {
        $id = $_POST['id'];
        $new_role = $_POST['new_role'];
        $query = "UPDATE users SET role = :role WHERE id = :id";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':role', $new_role);
        $stmt->bindParam(':id', $id);
        $stmt->execute();
    }

    if (isset($_POST['create_user'])) {
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

$total_query = "SELECT COUNT(*) FROM users";
$total_stmt = $pdo->prepare($total_query);
$total_stmt->execute();
$total_users = $total_stmt->fetchColumn();
$total_pages = ceil($total_users / $items_per_page);

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
    <style>
        /* Add responsive styles for tables and form */
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .pagination a {
            margin: 0 5px;
            padding: 10px 15px;
            text-decoration: none;
            color: #007bff;
            border: 1px solid #ddd;
        }
        .pagination a.active {
            background-color: #007bff;
            color: white;
        }
        .pagination {
            display: flex;
            justify-content: center;
            padding: 20px;
        }
        .form-container {
            margin: 20px 0;
        }
        .form-container form {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        .form-container input,
        .form-container select,
        .form-container button {
            padding: 10px;
            flex: 1;
            min-width: 200px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="links">
            <a href="index.php">Accueil</a>
            <a href="crudimage.php">Gestion des Animes</a>
            <a href="logout.php">Déconnexion</a>
        </div>
    </div>
    <div class="container">
        <h1>Gestion des Utilisateurs</h1>

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
                        <td><?php echo htmlspecialchars($user['id']); ?></td>
                        <td><?php echo htmlspecialchars($user['username']); ?></td>
                        <td><?php echo htmlspecialchars($user['role']); ?></td>
                        <td><?php echo $user['active'] ? 'Oui' : 'Non'; ?></td>
                        <td>
                            <form action="crud.php" method="POST" onsubmit="return confirm('Confirmer cette action?');" style="display:inline;">
                                <input type="hidden" name="id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                <select name="new_role">
                                    <option value="user" <?php if ($user['role'] === 'user') echo 'selected'; ?>>Utilisateur</option>
                                    <option value="admin" <?php if ($user['role'] === 'admin') echo 'selected'; ?>>Administrateur</option>
                                </select>
                                <button type="submit" name="change_role">Changer le rôle</button>
                            </form>
                            <?php if ($user['active']): ?>
                                <form action="crud.php" method="POST" onsubmit="return confirm('Confirmer cette action?');" style="display:inline;">
                                    <input type="hidden" name="id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                    <button type="submit" name="deactivate">Désactiver</button>
                                </form>
                            <?php else: ?>
                                <form action="crud.php" method="POST" onsubmit="return confirm('Confirmer cette action?');" style="display:inline;">
                                    <input type="hidden" name="id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                    <button type="submit" name="activate" style="background-color: red; color: white;">Activer</button>
                                </form>
                            <?php endif; ?>
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

        <div class="pagination">
            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                <a href="crud.php?page=<?php echo $i; ?>" class="pagination-link"><?php echo $i; ?></a>
            <?php endfor; ?>
        </div>
    </div>
</body>
</html>
