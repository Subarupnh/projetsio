<?php
session_start();

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
    <title>Page d'Accueil</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .anime-list {
            display: flex;
            flex-wrap: wrap;
        }
        .anime-item {
            width: 22%;
            margin: 1%;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            text-align: center;
            padding: 10px;
        }
        .anime-item img {
            max-width: 100%;
            height: auto;
        }
        .search-bar {
            margin-bottom: 20px;
            text-align: center;
        }
        .search-bar input {
            padding: 10px;
            width: 300px;
            font-size: 16px;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="links">
            <?php if (isset($_SESSION['username'])): ?>
                <a href="welcome.php">Bienvenue, <?php echo htmlspecialchars($_SESSION['username']); ?></a>
                <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
                    <a href="crud.php">Gestion des Utilisateurs</a>
                    <a href="crudimage.php">Gestion des Animes</a>
                <?php endif; ?>
                <a href="logout.php">Déconnexion</a>
            <?php else: ?>
                <a href="login_register.php?action=login">Connexion</a>
                <a href="login_register.php?action=register">Inscription</a>
            <?php endif; ?>
        </div>
    </div>

    <div class="container">
        <div class="search-bar">
            <input type="text" id="search" placeholder="Rechercher un anime...">
        </div>
        
        <div class="anime-list" id="animeList">
            <?php foreach ($animes as $anime): ?>
                <div class="anime-item">
                    <img src="images/<?php echo htmlspecialchars(basename($anime['image_path'])); ?>" alt="<?php echo htmlspecialchars($anime['title']); ?>">
                    <h3><?php echo htmlspecialchars($anime['title']); ?></h3>
                    <p><?php echo htmlspecialchars($anime['description']); ?></p>
                </div>
            <?php endforeach; ?>
        </div>
    </div>

    <script>
        document.getElementById('search').addEventListener('input', function() {
            var input = this.value.toLowerCase();
            var animeItems = document.getElementsByClassName('anime-item');
            Array.from(animeItems).forEach(function(item) {
                var title = item.getElementsByTagName('h3')[0].textContent.toLowerCase();
                if (title.includes(input)) {
                    item.style.display = '';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    </script>
</body>
</html>
