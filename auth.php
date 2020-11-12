<?php
class Auth {

    public $pdo;
    public $messages = [];

    public function __construct()
    {
        // $this->connect();
    }

    public function displayMessages()
    {
        foreach ($this->messages as $message) {
            echo $message . '<br>';
        }
    }

    public function connect()
    {
        $host = '127.0.0.1';
        $user = 'ubuntu';
        $password = '';
        $db = 'auth';

        $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        return $pdo;
    }

    public function registerUser($email, $password, $confirmPassword)
    {
        if (!$this->passwordsMatch($password, $confirmPassword)) {
            echo 'passwords don\'t match';
            return false;
        }

        $password = $this->sanitizeSpecialChars($password);
        $email = $this->sanitizeEmail($email);

        if (!$this->validatePassword($password)) {
            return false;
        } else {
            $password = $this->hashPassword($password);
        }

        if (!$this->userExists($email)) {
            $pdo = $this->connect();
            $sql = "INSERT INTO users (email, password, active) VALUES (:email, :password, 1)";
            $stmt = $pdo->prepare($sql);
            $stmt->bindValue(':email', $email);
            $stmt->bindValue(':password', $password);
            $stmt->execute();
            return true;
        } else {
            return false;
        }
    }

    public function loginUser($email, $password)
    {
        $password = $this->sanitizeSpecialChars($password);
        $email = $this->sanitizeEmail($email);

        $user = $this->getUserByEmail($email);

        if ($user) {
            if ($this->verifyPassword($user, $password)) {
                if ($this->addSession($user)) {
                    echo "Logged In";
                }
            }
        }

        $this->displayMessages();
    }

    public function addSession($user)
    {
        $pdo = $this->connect();
        $sql = "INSERT INTO user_sessions (user_id, ip, user_agent) VALUES (:user_id, :ip, :user_agent)";
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':user_id', $user->id);
        $stmt->bindValue(':ip', $this->getUserIP());
        $stmt->bindValue(':user_agent', $this->getUserAgent());

        if ($stmt->execute()) {
            $this->messages[] = 'Session added';
            return true;
        } else {
            $this->messages[] = 'Session failed';
            return false;
        }
    }

    public function verifyPassword($user, $password)
    {
        if (password_verify($password, $user->password)) {
            $this->messages[] = 'Password Verified';
            return true;
        } else {
            $this->messages[] = 'Password is wrong';
            return false;
        }
    }

    public function getUserByEmail($email)
    {
        $pdo = $this->connect();
        $sql = "SELECT * FROM users WHERE email = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$email]);
        if ($result = $stmt->fetch(PDO::FETCH_OBJ)) {
            $this->messages[] = 'User Found';
            return $result;
        } else {
            $this->messages[] = 'User not found';
            return false;
        }
    }


    public function hashPassword($password)
    {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    public function passwordsMatch($password, $confirmPassword)
    {
        return ($password === $confirmPassword) ? true : false;
    }

    public function validatePassword($password)
    {
        // Validate password strength
        $uppercase = preg_match('@[A-Z]@', $password);
        $lowercase = preg_match('@[a-z]@', $password);
        $number    = preg_match('@[0-9]@', $password);
        $specialChars = preg_match('@[^\w]@', $password);
        
        if(!$uppercase || !$lowercase || !$number || !$specialChars || strlen($password) < 8) {
            echo 'Password should be at least 8 characters in length and should include at least one upper case letter, one number, and one special character.';
            return false;
        }else{
            echo 'Strong password.';
            return true;
        }
    }

    public function userExists($email)
    {
        $pdo = $this->connect();
        $sql = "SELECT id FROM users WHERE email = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            echo 'user already exists';
            return true;
        } else {
            return false;
        }
    }

    public function userActive($email)
    {
        $pdo = $this->connect();
        $sql = "SELECT id FROM users WHERE email = ? AND active = 1";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            return true;
        } else {
            return false;
        }
    }

    public function sanitizeSpecialChars($value)
    {
        return htmlentities($value, ENT_QUOTES, 'UTF-8');
    }

    public function sanitizeEmail($email)
    {
        return filter_var($email, FILTER_SANITIZE_EMAIL);
    }

    public function getUserIP()
    {
        if (getenv('HTTP_CLIENT_IP')) {
            $ipAddress = getenv('HTTP_CLIENT_IP');
        } elseif (getenv('HTTP_X_FORWARDED_FOR')) {
            $ipAddress = getenv('HTTP_X_FORWARDED_FOR');
        } elseif (getenv('HTTP_X_FORWARDED')) {
            $ipAddress = getenv('HTTP_X_FORWARDED');
        } elseif (getenv('HTTP_FORWARDED_FOR')) {
            $ipAddress = getenv('HTTP_FORWARDED_FOR');
        } elseif (getenv('HTTP_FORWARDED')) {
            $ipAddress = getenv('HTTP_FORWARDED');
        } elseif (getenv('REMOTE_ADDR')) {
            $ipAddress = getenv('REMOTE_ADDR');
        } else {
            $ipAddress = '127.0.0.1';
        }

        return $ipAddress;
    }


    public function getUserAgent()
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? '';
    }


    // I know this is really silly but im lazy
    public static function br()
    {
        echo '<br>';
    }

}

$auth = new Auth;
