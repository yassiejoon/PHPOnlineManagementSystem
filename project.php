<?php

session_cache_limiter(false);
session_start();

require_once 'vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// create a log channel
$log = new Logger('main');
$log->pushHandler(new StreamHandler('logs/everything.log', Logger::DEBUG));
$log->pushHandler(new StreamHandler('logs/errors.log', Logger::ERROR));

require_once 'vendor/FlashMessages.php';
require_once 'local.php';


/*
  DB::$user = 'cp4776_ofms_wy ';
  DB::$password = 'Jg56AhAeGpmPa0ye';
  DB::$dbName = 'cp4776_ofms';
 */

DB::$error_handler = 'sql_error_handler';
DB::$nonsql_error_handler = 'nonsql_error_handler';

function nonsql_error_handler($params) {
    global $app, $log;
    $log->error("Database error: " . $params['error']);
    http_response_code(500);
    $app->render('error_internal.html.twig');
    die;
}

function sql_error_handler($params) {
    global $app, $log;
    $log->error("SQL error: " . $params['error']);
    $log->error(" in query: " . $params['query']);
    http_response_code(500);
    $app->render('error_internal.html.twig');
    die; // don't want to keep going if a query broke
}

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

$msg = new \Plasticbrain\FlashMessages\FlashMessages();
/*
  // Add a few messages
  $msg->info('This is an info message');
  $msg->success('This is a success message');
  $msg->warning('This is a warning message');
  $msg->error('This is an error message');

  // Display the messages
  $msg->display();
 */
if (!isset($_SESSION['todouser'])) {
    $_SESSION['todouser'] = array();
}

$twig = $app->view()->getEnvironment();
$twig->addGlobal('todouser', $_SESSION['todouser']);


$app->get('/', function() use ($app) {
    $app->render('register.html.twig');
});

// Login, Logout, and Register
// Register
$app->get('/register', function() use ($app) {
    $app->render('register.html.twig');
});

// Receiving a submission
$app->post('/register', function() use ($app) {
    // extract variables
    $email = $app->request()->post('email');
    $pass1 = $app->request()->post('pass1');
    $pass2 = $app->request()->post('pass2');
    $name = $app->request()->post('name');
    // list of values to retain after a failed submission
    $valueList = array(
        'email' => $email,
        'password' => $pass1,
        'name' => $name,
        'isAdmin' => 'no'
    );
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
        if (preg_match('/[A-Z]/', $pass1) != 1 || preg_match('/[a-z]/', $pass1) != 1 || preg_match('/[0-9]/', $pass1) != 1) {
            array_push($errorList, "Password must contain at least one lowercase, "
                    . "one uppercase letter, and a digit");
        }
    }
    //
    if ($errorList) {
        $app->render('register.html.twig', array("errorList" => $errorList));
        /* $msg = new \Plasticbrain\FlashMessages\FlashMessages();
          $msg->error($errorList);
          $msg->display(); */
    } else {
        DB::insert('users', $valueList);
        $app->render('register_success.html.twig');
    }
});

// AJAX: Is user with this email already registered?
$app->get('/ajax/emailused/:email', function($email) {
    $user = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email);
    //echo json_encode($user, JSON_PRETTY_PRINT);
    echo json_encode($user != null);
});


// Login
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
        $app->render('login.html.twig', array("error" => $error));

        /* $msg = new \Plasticbrain\FlashMessages\FlashMessages();
          $msg->error('Login failed try again.');
          $msg->display(); */
    } else {
        unset($user['password']);
        $_SESSION['todouser'] = $user;
        $app->render('login_success.html.twig');
    }
});

//Logout
$app->get('/logout', function() use ($app) {
    unset($_SESSION['todouser']);
    $app->render('logout.html.twig');
});

//User action: upload, list, rename, download and delete
//Upload
$app->get('/upload', function() use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('forbidden.html.twig');
        return;
    }
    $app->render('upload.html.twig');
});

$app->post('/upload', function() use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('forbidden.html.twig');
        return;
    }
    $errorList = array();
    $filename = isset($_FILES['filename']) ? $_FILES['filename'] : array();

    //
    if (!$filename) {
        array_push($errorList, "File is required to upload.");
    }
    //
    if ($errorList) {
        $app->render("upload.html.twig", array(
            "errorList" => $errorList
        ));
    } else {

        $filePath = "uploads/" . $filename["name"];
        move_uploaded_file($filename["name"], $filePath);
        DB::insert('files', array(
            "userId" => $_SESSION['todouser']['id'],
            "filename" => $filename["name"],
            "modifiedDate" => date('Y-m-d H:i:s'),
            "size" => $_FILES["filename"]["size"] / 1024
        ));
        $app->render("upload_success.html.twig", array(
            "filePath" => $filePath
        ));
    }
});

//List
$app->get('/list', function() use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('index_please_login.html.twig');
        return;
    }
    $userId = $_SESSION['todouser']['id'];
    $fileList = DB::query("SELECT * FROM files WHERE userId=%i", $userId);
    $app->render('filelist.html.twig', array('fileList' => $fileList));
});

//Rename
$app->get('/rename/:id', function($fileId) use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('forbidden.html.twig');
        return;
    }

    $file = DB::queryFirstRow("SELECT * FROM files WHERE id=%i", $fileId);
    print_r($file);
    $errorList = array();
    if (!$file) {
        array_push($errorList, "File is not selected.");
        $app->render('rename.html.twig', array("errorList" => $errorList));
    } else {
        $app->render('rename.html.twig', array(
            'f' => $file
        ));
    }
});

$app->post('/rename/:id', function($fileId) use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('forbidden.html.twig');
        return;
    }

    $filename = $app->request()->post('filename');
    $fileList = array(
        "filename" => $filename,
        "modifiedDate" => date('Y-m-d H:i:s'));

    DB::update('files', $fileList, "id = %i", $fileId);
    $app->render("rename_success.html.twig");
});

//Delete
$app->get('/delete/:id', function($fileId) use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('forbidden.html.twig');
        return;
    }
    $file = DB::queryFirstRow("SELECT * FROM files WHERE id=%i", $fileId);
    $errorList = array();
    if (!$file) {
        array_push($errorList, "File is not selected.");
        $app->render('delete.html.twig', $errorList);
    }
    $app->render('delete.html.twig', array(
        'f' => $file
    ));
});


$app->post('/delete/:id', function($fileId) use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('forbidden.html.twig');
        return;
    }
    DB::delete('files', "id = %i", $fileId);
    $app->render("delete_success.html.twig");
});

//Download
$app->get('/download', function() use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('forbidden.html.twig');
        return;
    }
    $app->render('rename.html.twig');
});

$app->post('/download', function() use ($app) {
    if (!$_SESSION['todouser']) {
        $app->render('forbidden.html.twig');
        return;
    }
});

//Admin action: list, edit, delete, and block
//List
$app->get('/admin/list', function() use ($app) {
    if ((!$_SESSION['todouser']) || ($_SESSION['todouser']['isAdmin'] != "yes")) {
        $app->render('forbidden.html.twig');
        return;
    }
    $userList = DB::query("SELECT * FROM users");
    $app->render('userlist.html.twig', array('userList' => $userList));
});

//Edit
$app->get('/admin/edit/:id', function($userId) use ($app) {
    if ((!$_SESSION['todouser']) || ($_SESSION['isAdmin'] != 'yes')) {
        $app->render('forbidden.html.twig');
        return;
    }
    $user = DB::queryFirstRow("SELECT * FROM users WHERE id=%i", $userId);
    $errorList = array();
    if (!$user) {
        array_push($errorList, "User is not selected.");
        $app->render('admin_edit.html.twig', $errorList);
    }
    $app->render('admin_edit.html.twig', array(
        'u' => $user
    ));
});

$app->post('/admin/edit/:id', function($userId) use ($app) {
    if ((!$_SESSION['todouser']) || ($_SESSION['isAdmin'] != 'yes')) {
        $app->render('forbidden.html.twig');
        return;
    }

    $isAdmin = $app->request()->post('isAdmin') ? 'yes' : 'no';
    $userList = array("isAdmin" => $isAdmin);

    DB::update('users', $userList, "id = %i", $fileId);
    $app->render("admin_edit_success.html.twig");
});

//Delete
$app->get('/admin/delete/:id', function($userId) use ($app) {
    if ((!$_SESSION['todouser']) || ($_SESSION['isAdmin'] != 'yes')) {
        $app->render('forbidden.html.twig');
        return;
    }

    $user = DB::queryFirstRow("SELECT * FROM users WHERE id=%i", $userId);
    $errorList = array();
    if (!$user) {
        array_push($errorList, "User is not selected.");
        $app->render('admin_delete.html.twig', $errorList);
    }
    $app->render('admin_delete.html.twig', array(
        'u' => $user
    ));
});

$app->post('/admin/delete/:id', function($userId) use ($app) {
    if ((!$_SESSION['todouser']) || ($_SESSION['isAdmin'] != 'yes')) {
        $app->render('forbidden.html.twig');
        return;
    }
    DB::delete('users', "id = %i", $userId);
    $app->render("admin_delete_success.html.twig");
});

//Block
$app->get('/admin/block', function() use ($app) {
    if ((!$_SESSION['todouser']) || ($_SESSION['isAdmin'] != 'yes')) {
        $app->render('forbidden.html.twig');
        return;
    }
    $app->render('rename.html.twig');
});

$app->post('/admin/block', function() use ($app) {
    if ((!$_SESSION['todouser']) || ($_SESSION['isAdmin'] != 'yes')) {
        $app->render('forbidden.html.twig');
        return;
    }
});

// FOR DIAGNOSTIC PURPOSES ONLY - REMOVE IN PRODUCTION
$app->get('/session', function() {
    print_r($_SESSION);
});

$app->run();
