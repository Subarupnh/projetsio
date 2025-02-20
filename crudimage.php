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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['update_anime'])) {
        $id = $_POST['id'];
        $title = $_POST['title'];
        $description = $_POST['description'];
        $image = $_FILES['image'];
        if ($image['type'] === 'image/png') {
            $target_dir = "images/";
            $target_file = $target_dir . basename($image['name']);
            if (move_uploaded_file($image['tmp_name'], $target_file)) {
                $query = "UPDATE animes SET title = :title, description = :description, image_path = :image_path WHERE id = :id";
                $stmt = $pdo->prepare($query);
                $stmt->bindParam(':title', $title);
                $stmt->bindParam(':description', $description);
                $stmt->bindParam(':image_path', $target_file);
                $stmt->bindParam(':id', $id);
                $stmt->execute();
            } else {
                echo "Une erreur s'est produite lors du téléchargement de l'image.";
            }
        } else {
            echo "Veuillez télécharger une image au format PNG.";
        }
    }

    if (isset($_POST['create_anime'])) {
        $title = $_POST['title'];
        $description = $_POST['description'];
        $image = $_FILES['image'];
        if ($image['type'] === 'image/png') {
            $target_dir = "images/";
            $target_file = $target_dir . basename($image['name']);
            if (move_uploaded_file($image['tmp_name'], $target_file)) {
                $query = "INSERT INTO animes (title, description, image_path) VALUES (:title, :description, :image_path)";
                $stmt = $pdo->prepare($query);
                $stmt->bindParam(':title', $title);
                $stmt->bindParam(':description', $description);
                $stmt->bindParam(':image_path', $target_file);
                
            } else {
                echo "Une erreur s'est produite lors du téléchargement de l'image.";
            }
        } else {
            echo "Veuillez télécharger une image au format PNG.";
        }
    }
}

$query = "SELECT * FROM animes";
$stmt = $pdo->prepare($query);
$stmt->execute();
$animes = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestion des Animes</title>
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
        .form-container {
            margin: 20px 0;
        }
        .form-container form {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        .form-container input,
        .form-container textarea,
        .form-container select,
        .form-container button {
            padding: 10px;
            flex: 1;
            min-width: 200px;
            margin-top: 10px;
        }
        img {
            width: 100px;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="links">
            <a href="index.php">Accueil</a>
            <a href="crud.php">Gestion des Utilisateurs</a>
            <a href="logout.php">Déconnexion</a>
        </div>
    </div>
    <div class="container">
        <h1>Gestion des Animes</h1>

        <div class="form-container">
            <h2>Ajouter un Nouvel Anime</h2>
            <form action="crudimage.php" method="POST" enctype="multipart/form-data">
                <input type="text" name="title" placeholder="Titre" required>
                <textarea name="description" placeholder="Description" required></textarea>
                <input type="file" name="image" accept="image/png" required>
                <button type="submit" name="create_anime">Ajouter l'anime</button>
            </form>
        </div>

        <div class="form-container">
            <h2>Modifier un Anime</h2>
            <form action="crudimage.php" method="POST" enctype="multipart/form-data">
                <select name="id" required>
                    <?php foreach ($animes as $anime): ?>
                        <option value="<?php echo htmlspecialchars($anime['id']); ?>"><?php echo htmlspecialchars($anime['title']); ?></option>
                    <?php endforeach; ?>
                </select>
                <input type="text" name="title" placeholder="Nouveau titre" required>
                <textarea name="description" placeholder="Nouvelle description" required></textarea>
                <input type="file" name="image" accept="image/png" required>
                <button type="submit" name="update_anime">Mettre à jour l'anime</button>
            </form>
        </div>

        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Titre</th>
                    <th>Description</th>
                    <th>Image</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($animes as $anime): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($anime['id']); ?></td>
                        <td><?php echo htmlspecialchars($anime['title']); ?></td>
                        <td><?php echo htmlspecialchars($anime['description']); ?></td>
                        <td><img src="<?php echo htmlspecialchars($anime['image_path']); ?>" alt="<?php echo htmlspecialchars($anime['title']); ?>"></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
