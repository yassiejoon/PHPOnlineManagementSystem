<?php

session_cache_limiter(false);
session_start();

require_once 'vendor/autoload.php';

//DB::$host = '127.0.0.1';
DB::$user = 'slimtodo';
DB::$password = 'EaOvdIy5OJkZhtGN';
DB::$dbName = 'slimtodo';
DB::$port = 3333;
DB::$encoding = 'utf8';



// Slim creation and setup
$app = new \Slim\Slim(array(
    'view' => new \Slim\Views\Twig()
        ));

$view = $app->view();
$view->parserOptions = array(
    'debug' => true,
    'cache' => dirname(__FILE__) . '/cache'
);
$view->setTemplatesDirectory(dirname(__FILE__) . '/templates');

if (!isset($_SESSION['todouser'])) {
    $_SESSION['todouser'] = array();
}

$twig = $app->view()->getEnvironment();
$twig->addGlobal('todouser', $_SESSION['todouser']);

/*
$app->get('/', function() use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('index_please_login.html.twig');
        return;
    }
    $userId = $_SESSION['todouser']['id'];
    $todoList = DB::query("SELECT * FROM todos WHERE ownerId=%i", $userId);
    print_r($todoList);
    //$app->render('index_todolist.html.twig');
});

// STATE 1: First show
$app->get('/register', function() use ($app) {
    $app->render('register.html.twig');
});

// Receiving a submission
$app->post('/register', function() use ($app) {
    // extract variables
    $email = $app->request()->post('email');
    $pass1 = $app->request()->post('pass1');
    $pass2 = $app->request()->post('pass2');
    // list of values to retain after a failed submission
    $valueList = array('email' => $email);
    // check for errors and collect error messages
    $errorList = array();
    if (filter_var($email, FILTER_VALIDATE_EMAIL) === FALSE) {
        array_push($errorList, "Email is invalid");
    } else {
        $user = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email);
        if ($user) {
            array_push($errorList, "Email already in use");
        }
    }
    if ($pass1 != $pass2) {
        array_push($errorList, "Passwors do not match");
    } else {
        if (strlen($pass1) < 6) {
            array_push($errorList, "Password too short, must be 6 characters or longer");
        } 
        if (preg_match('/[A-Z]/', $pass1) != 1
         || preg_match('/[a-z]/', $pass1) != 1
         || preg_match('/[0-9]/', $pass1) != 1) {
            array_push($errorList, "Password must contain at least one lowercase, "
                    . "one uppercase letter, and a digit");
        }
    }
    //
    if ($errorList) {
        $app->render('register.html.twig', array(
            'errorList' => $errorList,
            'v' => $valueList
        ));
    } else {
        DB::insert('users', array(
            'email' => $email,
            'password' => $pass1
        ));
        $app->render('register_success.html.twig');
    }
});

// AJAX: Is user with this email already registered?
$app->get('/ajax/emailused/:email', function($email) {
    $user = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email);
    //echo json_encode($user, JSON_PRETTY_PRINT);
    echo json_encode($user != null);    
});

// HOMEWORK 1: implement login form
$app->get('/login', function() use ($app) {
    $app->render('login.html.twig');
});

$app->post('/login', function() use ($app) {
//    print_r($_POST);    
    $email = $app->request()->post('email');
    $pass = $app->request()->post('pass');
    // verification    
    $error = false;
    $user = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email);
    if (!$user) {
        $error = true;
    } else {
        if ($user['password'] != $pass) {
            $error = true;
        }
    }
    // decide what to render
    if ($error) {
        $app->render('login.html.twig', array("error" => true));
    } else {
        unset($user['password']);
        $_SESSION['todouser'] = $user;
        $app->render('login_success.html.twig');
    }
});


$app->get('/add', function() use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('forbidden.html.twig');
        return;
    }
    $isDone = $app->request()->post('isDone') ? 'done' : 'pending';
    $valueList = array('task' => $task, 'dueDate' => $dueDate,
        'isDone' => $isDone);
    
    $app->render('add.html.twig');
});

$app->post('/add', function() use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('forbidden.html.twig');
        return;
    }
    print_r($_POST);
    $isDone = $app->request()->post('isDone');
    if ($isDone) {
        echo "yes it is!";
    }
    echo "<p>isDone: $isDone</p>";
});


$app->get('/logout', function() use ($app) {
    unset($_SESSION['todouser']);
    $app->render('logout.html.twig');
});

// FOR DIAGNOSTIC PURPOSES ONLY - REMOVE IN PRODUCTION
$app->get('/session', function() {
    print_r($_SESSION);
});

*/
$app->run();
