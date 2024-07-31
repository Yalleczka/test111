<?php
header('Content-Type: application/json');

$servername = "127.0.0.1";
$username = "root";
$password = "";
$dbname = "cypher";

function getwebhook() {
    $discord_logs_webhook = "https://discord.com/api/webhooks/1263602818582057113/yeOxQAJC_OJ76zYTnb-DTXzoP2mKAB9DeaN3V7e5N9YP371TfrXcg9SQ82F5Lm_4KOVq";
    return $discord_logs_webhook;
}


if ($_SERVER['HTTP_USER_AGENT'] !== 'Valve/Steam HTTP Client 1.0 (730)') {
    echo "hi, what are u doing here.. #1";
    //echo encodeResponse(['status' => 'error', 'message' => 'Invalid user agent']);
    exit();
}

if (!isset($_SERVER['HTTP_CUSTOM']) || $_SERVER['HTTP_CUSTOM'] !== 'cerberus') {
    echo "hi, what are u doing here.. #2";
    //echo encodeResponse(['status' => 'error', 'message' => 'Invalid custom header']);
    exit();
}


$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    echo encodeResponse(['status' => 'error', 'message' => 'Database connection failed']);
    exit();
}

$requestMethod = $_SERVER['REQUEST_METHOD'];

if ($requestMethod === 'POST') {
    if (!isset($_POST['action'])) {
        echo encodeResponse(['status' => 'error', 'message' => 'Action parameter missing']);
        exit();
    }

    if (!isset($_POST['data'])) {
        echo encodeResponse(['status' => 'error', 'message' => 'Data parameter missing']);
        exit();
    }

    $data = decryptData($_POST['data']);
    
    if (!validateTimestamp($data)) {
        http_response_code(400);
        echo encodeResponse(['status' => 'error', 'message' => 'Message is too old']);
        exit();
    }
    

    $action = decryptData($_POST['action']);
    if ($action === 'register') {
        registerUser($conn);
    } elseif ($action === 'login') {
        loginUser($conn);
    } elseif ($action === 'api_active') {
        echo encodeResponse(['status' => 'success', 'message' => 'API is active', 'loader_version' => '0.1']);
    } elseif ($action === 'redeem') {
        redeemKey($conn);
    } elseif ($action === 'createkey') {
        createKey($conn);
    } elseif ($action === 'banuser') {
        banUser($conn);
    } elseif ($action === 'load') {
        loadScript($conn);
    } elseif ($action === 'checksession') {
        checkSession($conn);
    } else {
        echo encodeResponse(['status' => 'error', 'message' => 'Invalid action']);
    }
} else {
    echo encodeResponse(['status' => 'error', 'message' => 'Method not allowed']);
}

function loadScript($conn) {
    if (!isset($_POST['username']) || !isset($_POST['password']) || !isset($_POST['hwid']) || !isset($_POST['script_name'])) {
        echo encodeResponse(['status' => 'error', 'message' => 'Missing parameters']);
        exit();
    }

    $username = $_POST['username'];
    $password = $_POST['password'];
    $hwid = $_POST['hwid'];
    $scriptName = $_POST['script_name'];

    $stmt = $conn->prepare("SELECT password, banned, ban_reason, hwid, subscriptions, discordid FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($storedPassword, $banned, $banReason, $storedHwid, $subscriptionsJson, $discordId);
    $stmt->fetch();
    $stmt->close();

    if ($banned) {
        echo encodeResponse(['status' => 'error', 'message' => 'User is banned with reason: ' . $banReason]);
        exit();
    } elseif ($password !== $storedPassword) {
        echo encodeResponse(['status' => 'error', 'message' => 'Invalid username or password']);
        exit();
    } elseif ($hwid !== $storedHwid) {
        echo encodeResponse(['status' => 'error', 'message' => 'Invalid HWID']);
        exit();
    }
 
    $subscriptions = json_decode($subscriptionsJson, true);
    if (!$subscriptions || !is_array($subscriptions)) {
        echo encodeResponse(['status' => 'error', 'message' => 'No active subcriptions']);
        exit();
    }

    $scriptStmt = $conn->prepare("SELECT source, cracked, expiration, webhook_url FROM scripts WHERE name = ? AND expiration >= CURDATE()");
    $scriptStmt->bind_param("s", $scriptName);
    $scriptStmt->execute();
    $scriptStmt->store_result();
    $scriptStmt->bind_result($scriptContent, $scriptCracked, $scriptExpiration, $scriptWebhook);
    $scriptExists = $scriptStmt->fetch();
    $scriptStmt->close();

    if (!$scriptExists) {
        echo encodeResponse(['status' => 'error', 'message' => 'Script not found or expired']);
        exit();
    }

    if ($scriptCracked == 1) {
        if (!isset($subscriptions["crack"]) || strtotime($subscriptions["crack"]) < time()) {
            echo encodeResponse(['status' => 'error', 'message' => 'Subscription expired or not active']);
            exit();
        }
    } else {
        if (!isset($subscriptions[$scriptName]) || strtotime($subscriptions[$scriptName]) < time()) {
            echo encodeResponse(['status' => 'error', 'message' => 'Subscription expired or not active']);
            exit();
        }
    }

    $discord_logs = getwebhook();
    if (!empty($discord_logs)) {
        $payload = json_encode([
            'content' => "User **$username** (<@$discordId>) has loaded the script **$scriptName**"
        ]);
    
        $ch = curl_init($discord_logs);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_exec($ch);
        curl_close($ch);
    }
    
    if (!empty($scriptWebhook)) {
        $payload = json_encode([
            'content' => "User **$username** (<@$discordId>) has loaded the script"
        ]);
    
        $ch = curl_init($scriptWebhook);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_exec($ch);
        curl_close($ch);
    }


    echo encodeResponse([
        'status' => 'success',
        'message' => 'Script loaded successfully',
        'script_content' => $scriptContent
    ]);
}



$conn->close();

function resetHWID($conn) {
    if (!isset($_POST['username'])) {
        echo encodeResponse(['status' => 'error', 'message' => 'Missing username']);
        exit();
    }

    $username = $_POST['username'];

    $stmt = $conn->prepare("UPDATE users SET hwid = NULL WHERE username = ?");
    $stmt->bind_param("s", $username);

    if ($stmt->execute()) {
        echo encodeResponse(['status' => 'success', 'message' => 'HWID reset successfully']);
    } else {
        echo encodeResponse(['status' => 'error', 'message' => 'HWID reset failed']);
    }

    $stmt->close();
    exit();
}


function redeemKey($conn) {
    if (!isset($_POST['username']) || !isset($_POST['key'])) {
        echo encodeResponse(['status' => 'error', 'message' => 'Missing parameters']);
        exit();
    }

    $username = $_POST['username'];
    $key = $_POST['key'];

    $keyStmt = $conn->prepare("SELECT minutes, name FROM script_keys WHERE `key` = ? AND used = 0");
    $keyStmt->bind_param("s", $key);
    $keyStmt->execute();
    $keyStmt->bind_result($minutes, $scriptName);
    $keyStmt->fetch();
    $keyStmt->close();

    if (empty($minutes)) {
        echo encodeResponse(['status' => 'error', 'message' => 'Invalid or already used key']);
        exit();
    }
    
    if ($scriptName !== "crack") {
        $scriptCheckStmt = $conn->prepare("SELECT name, webhook_url FROM scripts WHERE name = ?");
        $scriptCheckStmt->bind_param("s", $scriptName);
        $scriptCheckStmt->execute();
        $scriptCheckStmt->bind_result($scriptName, $webhookUrl);
        $scriptCheckStmt->store_result();
        
        if ($scriptCheckStmt->num_rows === 0) {
            echo encodeResponse(['status' => 'error', 'message' => 'Script does not exist anymore']);
            exit();
        }

        $scriptCheckStmt->fetch();
        $scriptCheckStmt->close();
    }

    $updateKeyStmt = $conn->prepare("UPDATE script_keys SET used = 1, used_by = ? WHERE `key` = ?");
    $updateKeyStmt->bind_param("ss", $username, $key);
    $updateKeyStmt->execute();
    $updateKeyStmt->close();

    $userStmt = $conn->prepare("SELECT subscriptions, discordid FROM users WHERE username = ?");
    $userStmt->bind_param("s", $username);
    $userStmt->execute();
    $userStmt->bind_result($subscriptionsJson, $discordId);
    $userStmt->fetch();
    $userStmt->close();

    $subscriptions = json_decode($subscriptionsJson, true);

    if (isset($subscriptions[$scriptName])) {
        $subscriptionExpiration = strtotime($subscriptions[$scriptName]);
        $newSubscriptionExpiration = $subscriptionExpiration > time() ? date('Y-m-d H:i:s', $subscriptionExpiration + $minutes * 60) : date('Y-m-d H:i:s', time() + $minutes * 60);
    } else {
        $newSubscriptionExpiration = date('Y-m-d H:i:s', time() + $minutes * 60);
    }

    $subscriptions[$scriptName] = $newSubscriptionExpiration;
    $updatedSubscriptionsJson = json_encode($subscriptions);

    $updateUserStmt = $conn->prepare("UPDATE users SET subscriptions = ? WHERE username = ?");
    $updateUserStmt->bind_param("ss", $updatedSubscriptionsJson, $username);
    $updateUserStmt->execute();
    $updateUserStmt->close();

    $discord_logs = getwebhook();
    if (!empty($discord_logs)) {
        $payload = json_encode([
            'content' => "User **$username** (<@$discordId>) has redeemed the key **$key**, for the script **$scriptName** - new subscription time: **$newSubscriptionExpiration**"
        ]);

        $ch = curl_init($discord_logs);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_exec($ch);
        curl_close($ch);
    }

    if (!empty($webhookUrl)) {
        $payload = json_encode([
            'content' => "User **$username** (<@$discordId>) has redeemed the key **$key**, new subscription time: **$newSubscriptionExpiration**"
        ]);

        $ch = curl_init($webhookUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_exec($ch);
        curl_close($ch);
    }

    echo encodeResponse(['status' => 'success', 'message' => 'Key redeemed successfully']);
}




function createKey($conn) {
    if (!isset($_POST['name']) || !isset($_POST['days']) || !isset($_POST['source'])) {
        echo encodeResponse(['status' => 'error', 'message' => 'Missing parameters']);
        exit();
    }

    $name = $_POST['name'];
    $days = $_POST['days'];

    if ($_POST['source'] !== 'cerberus-owner') {
        echo encodeResponse(['status' => 'error', 'message' => 'Unauthorized source']);
        return;
    }
    
    $checkStmt = $conn->prepare("SELECT COUNT(*) FROM scripts WHERE name = ?");
    $checkStmt->bind_param("s", $name);
    $checkStmt->execute();
    $checkStmt->bind_result($count);
    $checkStmt->fetch();
    $checkStmt->close();

    if ($count <= 0) {
        echo encodeResponse(['status' => 'error', 'message' => 'Script with that name doesnt exist']);
        return;
    }

    $key = generateRandomKey();
    
    $stmt = $conn->prepare("INSERT INTO script_keys (`key`, `days`, `name`) VALUES (?, ?, ?)");
    $stmt->bind_param("sis", $key, $days, $name);
    
    if ($stmt->execute()) {
        echo encodeResponse(['status' => 'success', 'message' => 'Key created successfully', 'key' => $key]);
    } else {
        echo encodeResponse(['status' => 'error', 'message' => 'Failed to create key']);
    }
    
    $stmt->close();
}


function generateRandomKey() {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $key = '';
    $length = 16;
    
    for ($i = 0; $i < $length; $i++) {
        $key .= $characters[rand(0, strlen($characters) - 1)];
    }
    
    return $key;
}

function registerUser($conn) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $hwid = $_POST['hwid'];
    $discordid = $_POST['discordid'];
    $registerip = $_SERVER['REMOTE_ADDR'];

    $checkStmt = $conn->prepare("SELECT username FROM users WHERE username = ?");
    $checkStmt->bind_param("s", $username);
    $checkStmt->execute();
    $checkStmt->store_result();
    
    if ($checkStmt->num_rows > 0) {
        echo encodeResponse(['status' => 'error', 'message' => 'Username already exists']);
        return;
    }

    $checkStmt->close();

    $session_id = generateRandomSessionId();
    $session_timestamp = time();
    

    $initialSubscriptions = json_encode([]);
    
    $stmt = $conn->prepare("INSERT INTO users (username, password, hwid, discordid, registerip, session_id, session_timestamp, subscriptions) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssssis", $username, $password, $hwid, $discordid, $registerip, $session_id, $session_timestamp, $initialSubscriptions);

    if ($stmt->execute()) {
        echo encodeResponse(['status' => 'success', 'message' => 'User registered successfully', 'session_id' => $session_id]);
    } else {
        echo encodeResponse(['status' => 'error', 'message' => 'User registration failed']);
    }

    $stmt->close();
}

function generateRandomSessionId() {
    return bin2hex(random_bytes(16));
}


function checkSession($conn) {
    if (!isset($_POST['username']) || !isset($_POST['session_id'])) {
        echo encodeResponse(['status' => 'error', 'message' => 'Username or session ID missing']);
        return;
    }

    $username = $_POST['username'];
    $session_id = $_POST['session_id'];

    $stmt = $conn->prepare("SELECT username, session_timestamp FROM users WHERE username = ? AND session_id = ?");
    $stmt->bind_param("ss", $username, $session_id);
    $stmt->execute();
    $stmt->bind_result($fetchedUsername, $sessionTimestamp);
    $stmt->fetch();
    $stmt->close();

    if (!$fetchedUsername) {
        echo encodeResponse(['status' => 'error', 'message' => 'Invalid session']);
        return;
    }

    $sessionExpiration = strtotime($sessionTimestamp) + 10;
    $currentTimestamp = strtotime(date('Y-m-d H:i:s')); 

    if ($currentTimestamp > $sessionExpiration) {
        echo encodeResponse(['status' => 'error', 'message' => 'Session expired']);
        return;
    } else {
        echo encodeResponse(['status' => 'success', 'message' => 'Session ID is correct']);
    }
}

function loginUser($conn) {
    if (!isset($_POST['username']) || !isset($_POST['password']) || !isset($_POST['hwid'])) {
        echo encodeResponse(['status' => 'error', 'message' => 'Missing parameters']);
        exit();
    }

    $username = $_POST['username'];
    $password = $_POST['password'];
    $hwid = $_POST['hwid'];

    $stmt = $conn->prepare("SELECT password, banned, ban_reason, hwid, subscriptions, lastip, last_login_date FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($storedPassword, $banned, $banReason, $storedHwid, $subscriptionsJson, $lastip, $lastLoginDate);
    $stmt->fetch();
    $stmt->close();

    if ($banned) {
        echo encodeResponse(['status' => 'error', 'message' => 'You have been banned with reason: ' . $banReason]);
        exit();
    } elseif ($password === $storedPassword) {
        if (!is_null($storedHwid) && $hwid !== $storedHwid) {
            echo encodeResponse(['status' => 'error', 'message' => 'Invalid HWID']);
            exit();
        }

        $subscriptions = json_decode($subscriptionsJson, true);

        $activeSubscriptions = [];
        $hasActiveCrackSubscription = false;
        $crackSubTill = time();

        foreach ($subscriptions as $scriptName => $expiration) {
            $scriptStmt = $conn->prepare("SELECT expiration, cracked FROM scripts WHERE name = ?");
            $scriptStmt->bind_param("s", $scriptName);
            $scriptStmt->execute();
            $scriptStmt->bind_result($scriptExpiration, $cracked);
            $scriptExists = $scriptStmt->fetch();
            $scriptStmt->close();

            if ($scriptName === 'crack') {
                $hasActiveCrackSubscription = true;
                $crackSubTill = $expiration;
            }

            if (!$scriptExists) {
                continue;
            }
            

            $current_time = time();
            $expiration_time = strtotime($expiration);
            $scriptExpiration_time = strtotime($scriptExpiration);
            $scriptExpired = $scriptExpiration_time < $current_time;
            $userExpired = $expiration_time < $current_time;

            if (!$scriptExpired && !$userExpired) {
                $activeSubscriptions[$scriptName] = $expiration;
            }
        }

        if ($hasActiveCrackSubscription) {
            $crackedScriptsStmt = $conn->prepare("SELECT name FROM scripts WHERE cracked = 1");
            $crackedScriptsStmt->execute();
            $crackedScriptsStmt->bind_result($crackedScriptName);
            while ($crackedScriptsStmt->fetch()) {
                $activeSubscriptions[$crackedScriptName] = $crackSubTill;
            }
            $crackedScriptsStmt->close();
        }

        $lastip = $_SERVER['REMOTE_ADDR'];
        $lastLoginDate = date('Y-m-d H:i:s');

        $session_id = generateRandomSessionId();
        $session_timestamp = date('Y-m-d H:i:s');

        $updateStmt = $conn->prepare("UPDATE users SET session_id = ?, session_timestamp = ?, lastip = ?, last_login_date = ? WHERE username = ?");
        $updateStmt->bind_param("sssss", $session_id, $session_timestamp, $lastip, $lastLoginDate, $username);
        $updateStmt->execute();
        $updateStmt->close();

        echo encodeResponse([
            'status' => 'success',
            'message' => 'Login successful, welcome ' . $username,
            'active_subscriptions' => $activeSubscriptions,
            'session_id' => $session_id
        ]);
    } else {
        echo encodeResponse(['status' => 'error', 'message' => 'Invalid username or password']);
    }

    if (is_null($storedHwid)) {
        $updateHwidStmt = $conn->prepare("UPDATE users SET hwid = ? WHERE username = ?");
        $updateHwidStmt->bind_param("ss", $hwid, $username);
        $updateHwidStmt->execute();
        $updateHwidStmt->close();
    }

    $lastip = $_SERVER['REMOTE_ADDR'];
    $lastLoginDate = date('Y-m-d H:i:s');
    $updateStmt = $conn->prepare("UPDATE users SET lastip = ?, last_login_date = ? WHERE username = ?");
    $updateStmt->bind_param("sss", $lastip, $lastLoginDate, $username);
    $updateStmt->execute();
    $updateStmt->close();

    exit();
}



function banUser($conn) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $hwid = $_POST['hwid'];
    $reason = $_POST['reason'];
    
    $stmt = $conn->prepare("SELECT discordid, password, hwid FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($discordId, $storedPassword, $storedHwid);
    $stmt->fetch();
    
    if ($stmt->num_rows === 0) {
        echo encodeResponse(['status' => 'error', 'message' => 'User not found']);
        return;
    }
    
    if ($password !== $storedPassword) {
        echo encodeResponse(['status' => 'error', 'message' => 'Invalid password']);
        return;
    }
    
    if ($hwid !== $storedHwid) {
        echo encodeResponse(['status' => 'error', 'message' => 'Invalid HWID']);
        return;
    }
    
    $stmt->close();
    
    $updateStmt = $conn->prepare("UPDATE users SET banned = 1, ban_reason = ? WHERE username = ?");
    $updateStmt->bind_param("si", $reason, $username);
    
    if ($updateStmt->execute()) {
        echo encodeResponse(['status' => 'success', 'message' => 'User banned successfully']);
    } else {
        echo encodeResponse(['status' => 'error', 'message' => 'Failed to ban user']);
    }
    
    $updateStmt->close();

    $discord_logs = getwebhook();
    if (!empty($discord_logs)) {
        $payload = json_encode([
            'content' => "User **$username** (<@$discordId>) has been banned for security breach: **$reason**"
        ]);

        $ch = curl_init($discord_logs);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_exec($ch);
        curl_close($ch);
    }
}



function validateTimestamp($timestamp) {
    $currentTimestamp = time();
    return ($currentTimestamp - $timestamp) <= 5;
}

function xorStr($data) {
    $key = "cerberus";
    $data = str_split($data);
    
    foreach ($data as $i => $char) {
        $data[$i] = chr(ord($char) ^ ord($key[$i % strlen($key)]));
    }
    
    return implode('', $data);
}

function encodeResponse($data) {
    $timestamp = time();
    $data['timestamp'] = $timestamp;
    $jsonData = json_encode($data);
    $encryptedData = xorStr($jsonData);
    return base64_encode($encryptedData);
}

function decryptData($data) {
    $encryptedData = base64_decode($data);
    $jsonData = xorStr($encryptedData);
    return $jsonData;
}

?>
