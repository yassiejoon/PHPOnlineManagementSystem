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

/*$msg = new \Plasticbrain\FlashMessages\FlashMessages();

  // Add a few messages
  $msg->info('This is an info message');
  $msg->success('This is a success message');
  $msg->warning('This is a warning message');
  $msg->error('This is an error message');

  // Display the messages
  $msg->display();
 */
if (!isset($_SESSION['user'])) {
    $_SESSION['user'] = array();
}

$twig = $app->view()->getEnvironment();
$twig->addGlobal('user', $_SESSION['user']);

\Slim\Route::setDefaultConditions(array(
    'lang' => '(en|fr)'
));

$app->get('(/:lang)/', function($lang = 'en') use ($app) {
    $app->render($lang . '/register.html.twig');
});

// Login, Logout, and Register
// Register
$app->get('(/:lang)/register', function($lang = 'en') use ($app) {
    $app->render($lang . '/register.html.twig');
});

// Receiving a submission
$app->post('(/:lang)/register', function($lang = 'en') use ($app) {
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
        'isAdmin' => 'no',
        'isActive' => 'yes'
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
        $app->render($lang . '/register.html.twig', array(
            "errorList" => $errorList
        ));
        /*  $msg = new \Plasticbrain\FlashMessages\FlashMessages();
        $msg->error($errorList);
        $msg->display(); */
    } else {
        DB::insert('users', $valueList);
        $app->render($lang . '/register_success.html.twig');
    }
});
/*
// AJAX: Is user with this email already registered?
$app->get('/ajax/emailused/:email', function($email) {
    $user = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email);
    //echo json_encode($user, JSON_PRETTY_PRINT);
    echo json_encode($user != null);
});
*/

// Login
$app->get('(/:lang)/login', function($lang = 'en') use ($app) {
    $app->render($lang . '/login.html.twig');
});

$app->post('(/:lang)/login', function($lang = 'en') use ($app) {
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
        $app->render($lang . '/login.html.twig', array("error" => $error));
        /*
        $msg = new \Plasticbrain\FlashMessages\FlashMessages();
        $msg->error('Login failed try again.');
        $msg->display(); */
    } else {
        unset($user['password']);
        $_SESSION['user'] = $user;
        if($user['isActive'] == 'no'){
            $app->render($lang . '/block.html.twig');
        }else{
        $app->render($lang . '/login_success.html.twig');
        }
    }
});
// PASSWORD RESET

function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

$app->map('/passreset', function () use ($app, $log) {
    // Alternative to cron-scheduled cleanup

    if ($app->request()->isGet()) {
        $app->render($lang . '/passreset.html.twig');
    } else {
        $email = $app->request()->post('email');
        $user = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email);
        if ($user) {
            $app->render($lang . '/passreset_success.html.twig');
            $secretToken = generateRandomString(50);

            // insert-update 
            DB::insertUpdate('/passresets', array(
                'userID' => $user['ID'],
                'secretToken' => $secretToken,
                'expiryDateTime' => date("Y-m-d H:i:s", strtotime("+5 minutes"))
            ));
            // email user
            $url = 'http://' . $_SERVER['SERVER_NAME'] . '(/:lang)/passreset/' . $secretToken;
            $html = $app->view()->render($lang . '/email_passreset.html.twig', array(
                'name' => $user['name'],
                'url' => $url
            ));
            $headers = "MIME-Version: 1.0\r\n";
            $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
            $headers .= "From: Noreply <noreply@ipd8.info>\r\n";
            $headers .= "To: " . htmlentities($user['name']) . " <" . $email . ">\r\n";

            mail($email, "Password reset from SlimShop", $html, $headers);
            $log->info("Password reset for $email email sent");
        } else {
            $app->render($lang . '/passreset.html.twig', array('error' => TRUE));
        }
    }
})->via('GET', 'POST');

$app->map('/passreset/:secretToken', function($secretToken) use ($app) {
    $row = DB::queryFirstRow("SELECT * FROM passresets WHERE secretToken=%s", $secretToken);
    if (!$row) {
        $app->render($lang . '/passreset_notfound_expired.html.twig');
        return;
    }
    if (strtotime($row['expiryDateTime']) < time()) {
        $app->render($lang . '/passreset_notfound_expired.html.twig');
        return;
    }
    //
    if ($app->request()->isGet()) {
        $app->render($lang . '/passreset_form.html.twig');
    } else {
        $pass1 = $app->request()->post('pass1');
        $pass2 = $app->request()->post('pass2');
        //  verify password quality and that pass1 matches pass2
        $errorList = array();
        $msg = verifyPassword($pass1);
        if ($msg !== TRUE) {
            array_push($errorList, $msg);
        } else if ($pass1 != $pass2) {
            array_push($errorList, "Passwords don't match");
        }
        //
        if ($errorList) {
            $app->render($lang . '/passreset_form.html.twig', array(
                'errorList' => $errorList
            ));
        } else {
            // success - reset the password
            DB::update('users', array(
                'password' => password_hash($pass1, CRYPT_BLOWFISH)
                    ), "ID=%d", $row['userID']);
            DB::delete('passresets', 'secretToken=%s', $secretToken);
            $app->render($lang . '/passreset_form_success.html.twig');
            $log->info("Password reset completed for " . $row['email'] . " uid=" . $row['userID']);
        }
    }
})->via('GET', 'POST');


$app->get('(/:lang)/scheduled/daily', function($lang = 'en') use ($app, $log) {
    DB::$error_handler = FALSE;
    DB::$throw_exception_on_error = TRUE;
    // PLACE THE ORDER
    // clean up old password reset requests
    try {
        DB::delete('passresets', "expiryDateTime < NOW()");
        $log->debug("Password resets clean up, removed " . DB::affectedRows());
    } catch (MeekroDBException $e) {
        sql_error_handler(array(
            'error' => $e->getMessage(),
            'query' => $e->getQuery()
        ));
    }

    echo "Completed";
});

//Logout
$app->get('(/:lang)/logout', function($lang = 'en') use ($app) {
    unset($_SESSION['user']);
    $app->render($lang . '/logout.html.twig');
});

//User action: upload, list, rename, download and delete
//Upload
$app->get('(/:lang)/upload', function($lang = 'en') use ($app) {
    if (!$_SESSION['user']&&($_SESSION['user']['isAdmin']!="yes")) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    $app->render($lang .'/upload.html.twig',array(
            "u" => $_SESSION['user']
        ));
});

$app->post('(/:lang)/upload', function($lang = 'en') use ($app) {
    if (!$_SESSION['user']&&($_SESSION['user']['isAdmin']!="yes")) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    $errorList = array();
    $file = isset($_FILES['filename']) ? $_FILES['filename'] : array();
    $userId = $_SESSION['user']['id'];
    $target_dir = "uploads/" . $userId . "/";
    if (!file_exists($target_dir)) {
        mkdir($target_dir, 0777, true);
    }
    
    $target_file = $target_dir . $_FILES["filename"]["name"];

    if (!$file) {
        array_push($errorList, "File is required to upload.");
    } else {
        $fileInfo = filesize($file["tmp_name"]);
        if (!$fileInfo) {
            array_push($errorList, "File does not look like an valid one");
        } else {
            // FIXME: opened a security hole here! .. must be forbidden
            if (strstr($file["name"], "..")) {
                array_push($errorList, "File name invalid");
            }
            // FIXME: do not allow file to override an previous upload
            if (file_exists($target_dir . $file['name'])) {
                array_push($errorList, "File name already exists. Will not override.");
            }
        }
    }
    if ($errorList) {
        $app->render($lang . "/upload.html.twig", array(
            "errorList" => $errorList
        ));
    } else {
        move_uploaded_file($_FILES["filename"]["tmp_name"], $target_file);

        DB::insert('files', array(
            "userId" => $_SESSION['user']['id'],
            "filename" => $file["name"],
            "modifiedDate" => date('Y-m-d H:i:s'),
            "size" => $_FILES["filename"]["size"] / 1024,
            "path" => $target_dir
        ));
        $app->render($lang . "/upload_success.html.twig",array(
            "u" => $_SESSION['user']
        ));
    }
});

//List
$app->get('(/:lang)/list', function($lang = 'en') use ($app) {
    if (!$_SESSION['user']&&($_SESSION['user']['isAdmin']!="yes")) {
        $app->render($lang . '/please_login.html.twig');
        return;
    }
    $userId = $_SESSION['user']['id'];
    $fileList = DB::query("SELECT * FROM files WHERE userId=%i", $userId);
    $app->render($lang . '/filelist.html.twig', array(
            'u' => $_SESSION['user'],
            'fileList' => $fileList
    ));
});

//Rename
$app->get('(/:lang)/rename/:id', function($lang = 'en', $fileId) use ($app) {
    if (!$_SESSION['user']&&($_SESSION['user']['isAdmin']!="yes")) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }

    $errorList = array();
    $fileList = DB::queryFirstRow("SELECT * FROM files WHERE id=%i", $fileId);
    $file = DB::queryFirstRow("SELECT filename FROM files WHERE id=%i", $fileId);
    $filestr = implode(" ", $file);

    if (!file_exists($fileList['path'] . $filestr)) {
        array_push($errorList, "File is not exist.");
        $app->render($lang . '/rename.html.twig', array("errorList" => $errorList));
    } else {
        $app->render($lang . '/rename.html.twig' ,array(
            'u' => $_SESSION['user'],
            'f' => $fileList
        ));
    }
});

$app->post('(/:lang)/rename/:id', function($lang = 'en', $fileId) use ($app) {
    if (!$_SESSION['user']&&($_SESSION['user']['isAdmin']!="yes")) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    $filename = $app->request()->post('filename');
    $fileList = array(
        "filename" => $filename,
        "modifiedDate" => date('Y-m-d H:i:s'));
    $file = DB::queryFirstRow("SELECT filename FROM files WHERE id=%i", $fileId);
    $path = DB::queryFirstRow("SELECT path FROM files WHERE id=%i", $fileId);
    $filestr = implode(" ", $file);
    $pathstr = implode(" ", $path);
    if (rename($pathstr. $filestr, $pathstr . $filename)) {
        DB::update('files', $fileList, "id = %i", $fileId);
        $app->render($lang . "/rename_success.html.twig", array(
            "u" => $_SESSION['user']
        ));
    }
});

//Delete
$app->get('(/:lang)/delete/:id', function($lang = 'en', $fileId) use ($app) {
    if (!$_SESSION['user']&&($_SESSION['user']['isAdmin']!="yes")) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    $errorList = array();
    $fileList = DB::queryFirstRow("SELECT * FROM files WHERE id=%i", $fileId);
    $file = DB::queryFirstRow("SELECT filename FROM files WHERE id=%i", $fileId);
    $filestr = implode(" ", $file);
    if (!file_exists($fileList['path'] . $filestr)) {
        array_push($errorList, "File is not exist.");
        $app->render($lang . '/delete.html.twig', $errorList);
    }

    $app->render($lang . '/delete.html.twig', array(
        'u' => $_SESSION['user'],
        'f' => $fileList
    ));
});


$app->post('(/:lang)/delete/:id', function($lang = 'en', $fileId) use ($app) {
    if (!$_SESSION['user']&&($_SESSION['user']['isAdmin']!="yes")) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    $file = DB::queryFirstRow("SELECT filename FROM files WHERE id=%i", $fileId);
    $fileList = DB::queryFirstRow("SELECT * FROM files WHERE id=%i", $fileId);
    $filestr = implode(" ", $file);
    if (unlink($fileList['path'] . $filestr)) {
        DB::delete('files', "id = %i", $fileId);
        $app->render($lang . "/delete_success.html.twig",array(
            "u" => $_SESSION['user']
        ));
    }
});

//Download
$app->get('(/:lang)/download/:id', function($lang = 'en', $fileId) use ($app) {
    if (!$_SESSION['user']&&($_SESSION['user']['isAdmin']!="yes")) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    $errorList = array();
    $fileList = DB::queryFirstRow("SELECT * FROM files WHERE id=%i", $fileId);
    $file = DB::queryFirstRow("SELECT filename FROM files WHERE id=%i", $fileId);
    $filestr = implode(" ", $file);
    if (!file_exists($fileList['path'] . $filestr)) {
        array_push($errorList, "File is not exist.");
        $app->render($lang . '/download.html.twig', $errorList);
    }

    $app->render($lang . '/download.html.twig', array(
        'u' => $_SESSION['user'],
        'f' => $fileList
    ));
});

$app->post('(/:lang)/download/:id', function($lang = 'en', $fileId) use ($app) {
    if (!$_SESSION['user']&&($_SESSION['user']['isAdmin']!="yes")) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }

    $filename = DB::queryFirstRow("SELECT filename FROM files WHERE id=%i", $fileId);
    $fileList = DB::queryFirstRow("SELECT * FROM files WHERE id=%i", $fileId);
    $file = implode(" ", $filename);
    $filepath = $fileList['path'] . $file;
    $app->view(new \SimoTod\SlimDownload\DownloadView());
    $app->render($filepath);
});

//Admin action: list, edit, delete, block, and view
//List
$app->get('(/:lang)/admin/list', function($lang = 'en') use ($app) {
    if ((!$_SESSION['user']) || ($_SESSION['user']['isAdmin'] != "yes")) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    $userList = DB::query("SELECT * FROM users");
    $app->render($lang . '/userlist.html.twig', array(
        'u' => $_SESSION['user'],
        'userList' => $userList
    ));
});

//View
$app->get('(/:lang)/admin/view', function($lang = 'en') use ($app) {
    if (($_SESSION['user']['isAdmin'] != 'yes')) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }

    $app->render($lang . '/admin_view.html.twig');
});

$app->post('(/:lang)/admin/view', function($lang = 'en') use ($app) {
    if (($_SESSION['user']['isAdmin'] != 'yes')) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }

    $userId = $app->request()->post('userId');

    $fileList = DB::query("SELECT * FROM files WHERE userId=%i", $userId);
    $app->render($lang . '/filelist.html.twig',array(
        'u' => $_SESSION['user'],
        'fileList' => $fileList
    ));
});

//Edit
$app->get('(/:lang)/admin/edit/:id', function($lang = 'en', $userId) use ($app) {
    if ((!$_SESSION['user']) || ($_SESSION['user']['isAdmin'] != 'yes')) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    $user = DB::queryFirstRow("SELECT * FROM users WHERE id=%i", $userId); 
    $app->render($lang . '/admin_edit.html.twig');
});

$app->post('(/:lang)/admin/edit/:id', function($lang = 'en', $userId) use ($app) {
    if ((!$_SESSION['user']) || ($_SESSION['user']['isAdmin'] != 'yes')) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }

    $isAdmin = $app->request()->post('isAdmin') ? 'yes' : 'no';
    $userList = array(
        "isAdmin" => $isAdmin
    );

    DB::update('users', $userList, "id = %i", $userId);
    $app->render($lang . "/admin_edit_success.html.twig");
});
//Block
$app->get('(/:lang)/admin/block/:id', function($lang = 'en', $userId) use ($app) {
    if ((!$_SESSION['user']) || ($_SESSION['user']['isAdmin'] != 'yes')) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    $user = DB::queryFirstRow("SELECT * FROM users WHERE id=%i", $userId);
    $app->render($lang . '/admin_block.html.twig', array(
        'user' => $user
    ));
});

$app->post('(/:lang)/admin/block/:id', function($lang = 'en', $userId) use ($app) {
    if ((!$_SESSION['user']) || ($_SESSION['user']['isAdmin'] != 'yes')) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }

    $isActive = $app->request()->post('isActive') ? 'no' : 'yes';
    $userList = array(
        "isActive" => $isActive
    );

    DB::update('users', $userList, "id = %i", $userId);
    $app->render($lang . "/admin_block_success.html.twig");
});


//Delete
$app->get('(/:lang)/admin/delete/:id', function($lang = 'en', $userId) use ($app) {
    if ((!$_SESSION['user']) || ($_SESSION['user']['isAdmin'] != 'yes')) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    $user = DB::queryFirstRow("SELECT * FROM users WHERE id=%i", $userId);
    $app->render($lang . '/admin_delete.html.twig', array(
        'u' => $user
    ));
});

$app->post('(/:lang)/admin/delete/:id', function($lang = 'en', $userId) use ($app) {
    if ((!$_SESSION['user']) || ($_SESSION['user']['isAdmin'] != 'yes')) {
        $app->render($lang . '/forbidden.html.twig');
        return;
    }
    DB::delete('users', "id = %i", $userId);
    $app->render($lang . "/admin_delete_success.html.twig");
});


// FOR DIAGNOSTIC PURPOSES ONLY - REMOVE IN PRODUCTION
$app->get('/session', function() {
    print_r($_SESSION);
});

$app->run();
