<?php

require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require '../libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

// User id from db - Global Variable
$user_id = NULL;

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();

    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        $db = new DbHandler();

        // get the api key
        $api_key = $headers['Authorization'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key);
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Api key is misssing";
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * User Registration
 * url - /user
 * method - POST
 * params - email, password
 */
$app->post('/user', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('email', 'password'));

            $response = array();

            // reading post params
            $email = $app->request->post('email');
            $password = $app->request->post('password');

            // validating email address
            validateEmail($email);

            // validating password
            validatePassword($password);

            $db = new DbHandler();
            $res = $db->createUser($email, $password);

            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "Đăng kí thành công. Vui lòng kích hoạt tài khoản qua email bạn vừa đăng kí!";

                $user = $db->getUserByEmail($email);
                $activation_code = $user["api_key"];

                $content_mail = "Chào bạn,<br>
                                Vui lòng nhấn vào đường link sau để kích hoạt tài khoản:
                                <a href='http://localhost/RESTFul/v1/user/". $activation_code.
                                "'>Kích hoạt tài khoản</a>";

                sendMail($email, $content_mail);
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Xin lỗi! Có lỗi xảy ra trong quá trình đăng kí.";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Xin lỗi! email bạn đăng kí đã tồn tại.";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/**
 * User activation
 * url - /user
 * method - GET
 * params - activation_code
 */
$app->get('/user/:activation_code', function($activation_code) {
            $response = array();

            $db = new DbHandler();
            $res = $db->activateUser($activation_code);

            if ($res == USER_ACTIVATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "Bạn đã kích hoạt tài khoản thành công.";
            } else if ($res == USER_ACTIVATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Xin lỗi! Kích hoạt tài khoản thất bại.";
            } 

            // echo json response
            echoRespnse(200, $response);
        });

/**
 * User Login
 * url - /user
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('email', 'password'));

            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();
            // check for correct email and password
            if ($db->checkLogin($email, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($email);

                if ($user != NULL) {
                    $response["error"] = false;
                    $response['email'] = $user['email'];
                    $response['apiKey'] = $user['api_key'];
                    $response['fullname'] = $user['fullname'];
                    $response['phone'] = $user['phone'];
                    $response['personalID'] = $user['personalID'];
                    $response['personalID_img'] = $user['personalID_img'];
                    $response['link_avatar'] = $user['link_avatar'];
                    $response['created_at'] = $user['created_at'];
                    $response['status'] = $user['status'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "Có lỗi xảy ra! Vui lòng thử lại.";
                }
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'Đăng nhập thất bại! Sai email hoặc mật khẩu.';
            }

            echoRespnse(200, $response);
        });

//Route itinerary
//
//
$app->post('/itinerary', 'authenticate', function() use ($app) {
            // check for required params
            //verifyRequiredParams(array('task'));

            $response = array();
            
            $start_address = $app->request->post('start_address');
            $end_address = $app->request->post('end_address');
            $leave_day = $app->request->post('leave_day');
            $duration = $app->request->post('duration');
            $cost = $app->request->post('cost');
            $description = $app->request->post('description');

            global $user_id;
            $db = new DbHandler();

            // creating new itinerary
            $itinerary_id = $db->createItinerary($user_id, $start_address, $end_address, $leave_day, $duration, $cost, $description);

            if ($itinerary_id != NULL) {
                $response["error"] = false;
                $response["message"] = "Itinerary created successfully";
                $response["itinerary_id"] = $itinerary_id;
                echoRespnse(201, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "Failed to create itinerary. Please try again";
                echoRespnse(200, $response);
            }            
        });

/**
 * Deleting itinerary. Users can delete only their itineraries
 * method DELETE
 * url /itinerary
 */
$app->delete('/itinerary/:id', 'authenticate', function($task_id) use($app) {
            global $user_id;

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteItinerary($user_id, $task_id);
            if ($result) {
                // itinerary deleted successfully
                $response["error"] = false;
                $response["message"] = "Itinerary deleted succesfully";
            } else {
                // itinerary failed to delete
                $response["error"] = true;
                $response["message"] = "Itinerary failed to delete. Please try again!";
            }
            echoRespnse(200, $response);
        });


/**
 * Updating user
 * method PUT
 * params task, status
 * url - /user
 */
$app->put('/user', 'authenticate', function() use($app) {
            // check for required params
            verifyRequiredParams(array('fullname', 'phone', 'personalID', 'personalID_img', 'link_avatar'));

            global $user_id;            
            $fullname = $app->request->put('fullname');
            $phone = $app->request->put('phone');
            $personalID = $app->request->put('personalID');
            $personalID_img = $app->request->put('personalID_img');
            $link_avatar = $app->request->put('link_avatar');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateUser($user_id, $fullname, $phone, $personalID, $personalID_img, $link_avatar);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = "Cập nhật thông tin thành công!";
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = "Cập nhật thông tin thất bại. Vui lòng thử lại!";
            }
            echoRespnse(200, $response);
        });

/**
 * Deleting task. Users can delete only their tasks
 * method DELETE
 * url /tasks
 */
$app->delete('/user/:user_id', 'authenticate', function($user_id) use($app) {
            global $user_id;

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteTask($user_id, $task_id);
            if ($result) {
                // task deleted successfully
                $response["error"] = false;
                $response["message"] = "Xóa người dùng thành công!";
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = "Xóa người dùng thất bại. Vui lòng thử lại!";
            }
            echoRespnse(200, $response);
        });

/**
 * Listing all tasks of particual user
 * method GET
 * url /tasks          
 */
$app->get('/tasks', 'authenticate', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetching all user tasks
            $result = $db->getAllUserTasks($user_id);

            $response["error"] = false;
            $response["tasks"] = array();

            // looping through result and preparing tasks array
            while ($task = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["id"] = $task["id"];
                $tmp["task"] = $task["task"];
                $tmp["status"] = $task["status"];
                $tmp["createdAt"] = $task["created_at"];
                array_push($response["tasks"], $tmp);
            }

            echoRespnse(200, $response);
        });

/**
 * Listing single task of particual user
 * method GET
 * url /tasks/:id
 * Will return 404 if the task doesn't belongs to user
 */
$app->get('/tasks/:id', function($task_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getTask($task_id, $user_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response["id"] = $result["id"];
                $response["task"] = $result["task"];
                $response["status"] = $result["status"];
                $response["createdAt"] = $result["created_at"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });

/**
 * Creating new task in db
 * method POST
 * params - name
 * url - /tasks/
 */
$app->post('/tasks', 'authenticate', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('task'));

            $response = array();
            $task = $app->request->post('task');

            global $user_id;
            $db = new DbHandler();

            // creating new task
            $task_id = $db->createTask($user_id, $task);

            if ($task_id != NULL) {
                $response["error"] = false;
                $response["message"] = "Task created successfully";
                $response["task_id"] = $task_id;
                echoRespnse(201, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "Failed to create task. Please try again";
                echoRespnse(200, $response);
            }            
        });

/**
 * Updating existing task
 * method PUT
 * params task, status
 * url - /tasks/:id
 */
$app->put('/tasks/:id', 'authenticate', function($task_id) use($app) {
            // check for required params
            verifyRequiredParams(array('task', 'status'));

            global $user_id;            
            $task = $app->request->put('task');
            $status = $app->request->put('status');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateTask($user_id, $task_id, $task, $status);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = "Task updated successfully";
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = "Task failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Deleting task. Users can delete only their tasks
 * method DELETE
 * url /tasks
 */
$app->delete('/tasks/:id', 'authenticate', function($task_id) use($app) {
            global $user_id;

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteTask($user_id, $task_id);
            if ($result) {
                // task deleted successfully
                $response["error"] = false;
                $response["message"] = "Task deleted succesfully";
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = "Task failed to delete. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }

    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Validating password
 */
function validatePassword($password) {
    $app = \Slim\Slim::getInstance();

    if (strlen( ($password) < '6') || (strlen($password) > '12') ) {
        $response["error"] = true;
        $response["message"] = 'Độ dài mật khẩu phải nằm trong khoảng 6 đến 12 kí tự!';
        echoRespnse(400, $response);
        $app->stop();
    } 

    if (preg_match('#[\\s]#', $password)) {
        $response["error"] = true;
        $response["message"] = 'Mật khẩu không được có khoảng trống!';
        echoRespnse(400, $response);
        $app->stop();
    } 
}

/**
 * Send activation email
 */
function sendMail($receiver_mail, $content) {
    require_once '../libs/PHPMailer/class.phpmailer.php';

    $mail               = new PHPMailer();
    $body               = $content;
    $body               = eregi_replace("[\]",'',$body);
    $mail->IsSMTP();

    $mail->SMTPAuth     = true;                  // enable SMTP authentication
    $mail->SMTPSecure   = "ssl";                 // sets the prefix to the servier
    $mail->Host         = "smtp.gmail.com";      // sets GMAIL as the SMTP server
    $mail->Port         = 465;                   // set the SMTP port for the GMAIL server
    $mail->Username     = "thanhbkdn92@gmail.com";  // GMAIL username
    $mail->Password     = "thanhkdt123";            // GMAIL password

    $mail->SetFrom('thanhbkdn92@gmail.com', 'Ride Sharing Verification Team'); //Sender

    $mail->Subject    = "Activate account"; //Subject

    $mail->AltBody    = "Để xem tin này, vui lòng bật tương thích chế độ hiển thị mã HTML!"; // optional, comment out and test

    $mail->MsgHTML($body);

    $address = $receiver_mail; //Receiver
    $mail->AddAddress($address, "Test"); //Send to?

    // $mail->AddAttachment("dinhkem/02.jpg");      // Attach
    // $mail->AddAttachment("dinhkem/200_100.jpg"); // Attach

    if(!$mail->Send()) {
      return "Lỗi gửi mail: " . $mail->ErrorInfo;
    } else {
      return "Mail đã được gửi!";
    }
}

/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);

    // setting response content type to json
    $app->contentType('application/json');

    echo json_encode($response);
}

$app->run();
?>