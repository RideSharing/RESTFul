<?php

require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require '../libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

// User id from db - Global Variable
$user_id = NULL;
// Staff id from db - Global Variable
$staff_id = NULL;
//Restricted user field
$restricted_user_field = array('user_id', 'email', 'api_key', 'created_at', 'status');


/**
 * Adding Middle Layer to authenticate User every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticateUser(\Slim\Route $route) {
    if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
        require_once '../include/lang_'.$_GET['lang'].'.php';
    } else {
        $language = 'en';
        require_once '../include/lang_en.php';
    }
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
        if (!$db->isValidApiKey($api_key,"user") || $db->isLockUser($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = $lang['ERR_ACCESS_DENIED'];
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
        $response["message"] = $lang['ERR_API_MISSING'];
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Adding Middle Layer to authenticate Staff every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticateStaff(\Slim\Route $route) {
    if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
        require_once '../include/lang_'.$_GET['lang'].'.php';
    } else {
        $language = 'en';
        require_once '../include/lang_en.php';
    }
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
        if (!$db->isValidApiKey($api_key,"staff")) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = $lang['ERR_ACCESS_DENIED'];
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $staff_id;
            // get user primary key id
            $staff_id = $db->getStaffId($api_key);
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = $lang['ERR_API_MISSING'];
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
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('email', 'password'), $language);

            $response = array();

            // reading post params
            $email = $app->request->post('email');
            $password = $app->request->post('password');

            // validating email address
            validateEmail($email, $language);
            // validating password
            validatePassword($password, $language);

            $db = new DbHandler();
            $res = $db->createUser($email, $password);

            if ($res == USER_CREATED_SUCCESSFULLY) {
                $user = $db->getUserByEmail($email);
                $activation_code = $user["api_key"];

                $content_mail = "Chao ban,<br>
                                Vui long nhan vao duong link sau de kich hoat tai khoan:
                                <a href='http://192.168.10.132/WebApp/controller/register.php?active_key=". $activation_code.
                                "'>Kich hoat tai khoan</a>";

                if (sendMail($email, $content_mail, "Active Account")) {
                    $response["error"] = false;
                    $response["message"] = $lang['REGISTER_USER_SUCCESS'];
                } else {
                    $response["error"] = true;
                    $response["message"] = $lang['ERR_SEND_EMAIL'];
                }
                
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = $lang['ERR_REGISTER'];
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = $lang['ERR_EMAIL_EXIST'];
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
$app->get('/active/:activation_code', function($activation_code) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();

            $db = new DbHandler();
            $res = $db->activateUser($activation_code);

            if ($res == USER_ACTIVATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = $lang['ACTIVATED_ACCOUNT_SUCCESS'];
            } else if ($res == USER_ACTIVATE_FAILED) {
                $response["error"] = true;
                $response["message"] = $lang['ERR_ACTIVATED_ACCOUNT'];
            } 

            // echo json response
            echoRespnse(200, $response);
        });

/**
 * User Login
 * url - /user/login
 * method - POST
 * params - email, password
 */
$app->post('/user/login', function() use ($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('email', 'password'), $language);

            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();

            $res = $db->checkLogin($email, $password);
            // check for correct email and password
            if ($res == LOGIN_SUCCESSFULL) {
                // get the user by email
                $user = $db->getUserByEmail($email);

                if ($user != NULL) {
                    $response["error"] = false;
                    $response['apiKey'] = $user['api_key'];
                    $response['customer_status'] = $user['status'];
                    $response['link_avatar'] = $user['link_avatar'];
                    $response['fullname'] = $user['fullname'];

                    $user_id = $db->getUserId($user['api_key']);

                    if ($db->isDriver($user_id)) {
                        $driver_status = $db->getDriverByField($user_id, 'status');
                        $response['driver_status'] = $driver_status;
                        $response['driver'] = true;
                    } else {
                        $response['driver'] = false;
                    }
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = $lang['ERR_LOGIN'];
                }
            } elseif ($res == WRONG_PASSWORD || $res == USER_NOT_REGISTER) {
                $response['error'] = true;
                $response['message'] = $lang['ERR_EMAIL_PASS'];
            } elseif ($res == USER_NOT_ACTIVATE) {
                $response['error'] = true;
                $response['message'] = $lang['ERR_ACTIVATED_ACCOUNT'];
            } elseif($res == USER_LOCKED) {
                $response['error'] = true;
                $response['message'] = $lang['ERR_ACOUNT_LOCKED'];
            }
            else{
                $response['error'] = true;
                $response['message'] = $lang['ERR_LOGIN_CHECK'];
            }

            echoRespnse(200, $response);
        });

$app->get('/forgotpass/:email', function($email) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();

            $db = new DbHandler();

            if ($db->isUserExists($email)) {
                $res = $db->getUserByEmail($email);

                if (isset($res)) {
                    $content_mail = "Chao ban,<br>
                                Vui long nhan vao duong link sau de doi mat khau:
                                <a href='http://192.168.10.74/WebApp/forgotpass.php?api_key=". $res['api_key'].
                                "'>Doi mat khau</a>";

                    sendMail($email, $content_mail, "Reset password");

                    $response["error"] = false;
                    $response["message"] = $lang['ALERT_SENT_EMAIL'];
                } else {
                    $response["error"] = true;
                    $response["message"] = $lang['ERROR_ACTIVATED'];
                } 
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_TYPE_EMAIL'];
            }
            // echo json response
            echoRespnse(200, $response);
        });

/**
 * Get user information
 * method GET
 * url /user
 * header - Authorization: API Key
 */
$app->get('/user', 'authenticateUser', function() {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getUserByUserID($user_id);

            if ($result != NULL) {
                $response['error'] = false;
                $response['email'] = $result['email'];
                $response['apiKey'] = $result['api_key'];
                $response['fullname'] = $result['fullname'];
                $response['phone'] = $result['phone'];
                $response['personalID'] = $result['personalID'];
                $response['personalID_img'] = $result['personalID_img'];
                $response['link_avatar'] = $result['link_avatar'];
                $response['created_at'] = $result['created_at'];
                $response['status'] = $result['status'];
                $response['locked'] = $result['locked'];
                echoRespnse(200, $response);
            } else {
                $response['error'] = true;
                $response['message'] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

/**
 * Get user's field information
 * method GET
 * url /user/:field (field is name of field want to get information)
 * header - Authorization: API Key
 */
$app->get('/user/:field', 'authenticateUser', function($field) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getUserByField($user_id, $field);

            if ($result != NULL || $field == 'locked') {
                $response["error"] = false;
                $response[$field] = $result;
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

/**
 * Updating user
 * method PUT
 * params fullname, phone, personalID, personalID_img, link_avatar
 * url - /user
 * header - Authorization: API Key
 */
$app->put('/user', 'authenticateUser', function() use($app) {
            global $user_id;   

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

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
                $response['error'] = false;
                $response['message'] = $lang['ALERT_UPDATE'];
            } else {
                // task failed to update
                $response['error'] = true;
                $response['message'] = $lang['ERR_UPDATE'];
            }
            echoRespnse(200, $response);
        });

/**
 * Update user information
 * method PUT
 * url /user/:field (field is name of field want to update)
 * params value
 * header - Authorization: API Key
 */
$app->put('/user/:field', 'authenticateUser', function($field) use($app) {
            global $restricted_user_field;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            if (!in_array($field, $restricted_user_field)) {
                // check for required params
                verifyRequiredParams(array('value'), $language);
                global $user_id;
                $value = $app->request->put('value');

                $response = array();
                $db = new DbHandler();

                if ($field == 'password') {
                    validatePassword($value, $language);

                    $result = $db->changePassword($user_id, $value);
                } else {
                    // fetch user
                    $result = $db->updateUserField($user_id, $field, $value);
                }

                if ($result) {
                    // user updated successfully
                    $response["error"] = false;
                    $response["message"] = $lang['ALERT_UPDATE'];
                } else {
                    // user failed to update
                    $response["error"] = true;
                    $response["message"] = $lang['ERR_UPDATE'];
                }
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_UPDATE'];
            }
            
            echoRespnse(200, $response);
        });

/**
 * Deleting user.
 * method DELETE
 * url /user
 */
$app->delete('/user', 'authenticateUser', function() {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteUser($user_id);

            if ($result) {
                // user deleted successfully
                $response["error"] = false;
                $response["message"] = $lang['USER_DELETE_SUCCESS'];
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = $lang['USER_DELETE_FAILURE'];
            }
            echoRespnse(200, $response);
        });

/**
 * Driver Registration
 * url - /driver
 * method - POST
 * params - driver
 */
$app->post('/driver', 'authenticateUser', function() use ($app) {
            verifyRequiredParams(array('driver_license', 'driver_license_img'), $language);
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();

            // reading post params
            $driver_license = $app->request->post('driver_license');
            $driver_license_img = $app->request->post('driver_license_img');

            $db = new DbHandler();
            $res = $db->createDriver($user_id, $driver_license, $driver_license_img);

            if ($res == DRIVER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = $lang['REGISTER_SUCCESS'];
            } else if ($res == DRIVER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = $lang['REGISTER_DRIVER'];
            } else if ($res == DRIVER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = $lang['ERR_REGISTER'];
            }
            // echo json response
            echoRespnse(201, $response);
        });

/**
 * Get driver information
 * method GET
 * url /driver
 */
$app->get('/driver', 'authenticateUser', function() {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getDriverByUserID($user_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response['driver_license'] = $result['driver_license'];
                $response['driver_license_img'] = $result['driver_license_img'];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

/**
 * Get user information
 * method GET
 * url /user
 */
$app->get('/driver/:field', 'authenticateUser', function($field) {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getDriverByField($user_id, $field);

            if ($result != NULL) {
                $response["error"] = false;
                $response[$field] = $result;
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(200, $response);
            }
        });

/**
 * Updating user
 * method PUT
 * params task, status
 * url - /user
 */
$app->put('/driver', 'authenticateUser', function() use($app) {
            // check for required params
            verifyRequiredParams(array('driver_license', 'driver_license_img'), $language);

            global $user_id;  

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }  

            $driver_license = $app->request->put('driver_license');
            $driver_license_img = $app->request->put('driver_license_img');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateDriver($user_id, $driver_license, $driver_license_img);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = $lang['ALERT_UPDATE'];
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['ERR_UPDATE'];
            }
            echoRespnse(200, $response);
        });

/**
 * Update user information
 * method PUT
 * url /user
 */
$app->put('/driver/:field', 'authenticateUser', function($field) use($app) {
            // check for required params
            verifyRequiredParams(array('value'), $language);
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $value = $app->request->put('value');

            $response = array();
            $db = new DbHandler();

            // fetch user
            $result = $db->updateDriverField($user_id, $field, $value);

            if ($result) {
                // user updated successfully
                $response["error"] = false;
                $response["message"] = $lang['ALERT_UPDATE'];
            } else {
                // user failed to update
                $response["error"] = true;
                $response["message"] = $lang['ERR_UPDATE'];
            }
            
            echoRespnse(200, $response);
        });

/**
 * Deleting user.
 * method DELETE
 * url /user
 */
$app->delete('/driver', 'authenticateUser', function() {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteDriver($user_id);

            if ($result) {
                // user deleted successfully
                $response["error"] = false;
                $response["message"] = $lang['DRIVER_DELETE_SUCCESS'];
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = $lang['DRIVER_DELETE_FAILURE'];
            }
            echoRespnse(200, $response);
        });

/**
 * Staff Registration
 * url - /staff
 * method - POST
 * params - email, password
 */
$app->post('/staff', function() use ($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('email'), $language);

            $response = array();

            // reading post params
            $role = $app->request->post('role');
            $email = $app->request->post('email');
            $fullname = $app->request->post('fullname');
            $personalID = $app->request->post('personalID');

            // validating email address
            validateEmail($email, $language);

            $db = new DbHandler();
            $res = $db->createStaff($role, $email, $fullname, $personalID);

            if ($res == STAFF_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = $lang['CREATE_STAFF_SUCCESS'];
            } else if ($res == STAFF_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = $lang['ERR_EMAIL_EXIST'];
            } else if ($res == STAFF_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = $lang['ERR_REGISTER'];
            }
            // echo json response
            echoRespnse(201, $response);
        });

/**
 * User Login
 * url - /user
 * method - POST
 * params - email, password
 */
$app->post('/staff/login', function() use ($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('email', 'password'), $language);

            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();

            $res = $db->checkLoginStaff($email, $password);
            // check for correct email and password
            if ($res == LOGIN_SUCCESSFULL) {
                // get the user by email
                $staff = $db->getStaffByEmail($email);

                if ($staff != NULL) {
                    $response["error"] = false;
                    $response['apiKey'] = $staff['api_key'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = $lang['ERR_LOGIN'];
                }
            } elseif ($res == WRONG_PASSWORD || $res == STAFF_NOT_REGISTER) {
                $response['error'] = true;
                $response['message'] = $lang['ERR_EMAIL_PASS'];
            }

            echoRespnse(200, $response);
        });

/**
 * Get all user information
 * method GET
 * url /user
 */
$app->get('/staff', 'authenticateStaff', function() {
            global $staff_id;

            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getStaffByStaffID($staff_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response['role'] = $result['role'];
                $response['email'] = $result['email'];
                $response['apiKey'] = $result['api_key'];
                $response['fullname'] = $result['fullname'];
                $response['personalID'] = $result['personalID'];
                $response['created_at'] = $result['created_at'];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

$app->get('/staffs', 'authenticateStaff', function() {
            $db = new DbHandler();

            // fetch task
            $result = $db->getListStaff();

            if ($result != NULL) {
                $response['error'] = false;
                $response['staffs'] = array();

                while ($staff = $result->fetch_assoc()) {
                    array_push($response['staffs'], $staff);               
                }

                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

$app->get('/staff/:staff_id', 'authenticateStaff', function($staff_id) {
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getStaffByStaffID($staff_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response['email'] = $result['email'];
                $response['apiKey'] = $result['api_key'];
                $response['fullname'] = $result['fullname'];
                $response['personalID'] = $result['personalID'];
                $response['link_avatar'] = $result['link_avatar'];
                $response['created_at'] = $result['created_at'];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

/**
 * Get all user information
 * method GET
 * url /user
 */
$app->get('/staff/user', 'authenticateStaff', function() {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            $response['error'] = false;
            $response['users'] = array();

            // fetch task
            $result = $db->getListUser();

            while ($user = $result->fetch_assoc()) {
                array_push($response['users'], $user);               
            }

            echoRespnse(200, $response);
        });

/**
 * Get user information
 * method GET
 * url /staff/user
 */
$app->get('/staff/user/:user_id', 'authenticateStaff', function($user_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getUserByUserID($user_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response['email'] = $result['email'];
                $response['apiKey'] = $result['api_key'];
                $response['fullname'] = $result['fullname'];
                $response['phone'] = $result['phone'];
                $response['personalID'] = $result['personalID'];
                $response['personalID_img'] = $result['personalID_img'];
                $response['link_avatar'] = $result['link_avatar'];
                $response['created_at'] = $result['created_at'];
                $response['status'] = $result['status'];
                $response['locked'] = $result['locked'];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });

/**
 * Get user information
 * method GET
 * url /user
 */
$app->get('/staff/user/:user_id/:field', 'authenticateStaff', function($user_id, $field) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getUserByField($user_id, $field);

            if ($result != NULL) {
                $response["error"] = false;
                $response[$field] = $result;
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

/**
 * Updating user
 * method PUT
 * params task, status
 * url - /user
 */
$app->put('/staff/user/:user_id', 'authenticateStaff', function($user_id) use($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('status', 'locked'), $language);
        
            $status = $app->request->put('status');
            $locked = $app->request->put('locked');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateUser1($user_id, $status, $locked);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = $lang['ALERT_UPDATE'];
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['ERR_UPDATE'];
            }
            echoRespnse(200, $response);
        });

/**
 * Update user information
 * method PUT
 * url /user
 */
$app->put('/staff/user/:user_id/:field', 'authenticateStaff', function($user_id, $field) use($app) {
            global $restricted_user_field;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            if (!in_array($field, $restricted_user_field)) {
                // check for required params
                verifyRequiredParams(array('value'), $language);

                $value = $app->request->put('value');

                $response = array();
                $db = new DbHandler();

                if ($field == 'password') {
                    validatePassword($value, $language);

                    $result = $db->changePassword($user_id, $value);
                } else {
                    // fetch user
                    $result = $db->updateUserField($user_id, $field, $value);
                }

                if ($result) {
                    // user updated successfully
                    $response["error"] = false;
                    $response["message"] = $lang['ALERT_UPDATE'];
                } else {
                    // user failed to update
                    $response["error"] = true;
                    $response["message"] = $lang['ERR_UPDATE'];
                }
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_UPDATE'];
            }
            
            echoRespnse(200, $response);
        });

/**
 * Deleting user.
 * method DELETE
 * url /staff/user
 */
$app->delete('/staff/user/:user_id', 'authenticateStaff', function($user_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteUser($user_id);

            if ($result) {
                // user deleted successfully
                $response["error"] = false;
                $response["message"] = $lang['USER_DELETE_SUCCESS'];
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = $lang['USER_DELETE_FAILURE'];
            }
            echoRespnse(200, $response);
        });

/**
 * Listing all itineraries of particual user
 * method GET
 * url /itineraries          
 */
$app->get('/staff/itineraries', 'authenticateStaff', function() {
            global $staff_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetching all user tasks
            $result = $db->getAllItinerariesWithDriverInfo();

            $response["error"] = false;
            $response["itineraries"] = array();

            // looping through result and preparing tasks array
            while ($itinerary = $result->fetch_assoc()) {
                $tmp = array();

                //itinerary info
                $tmp["itinerary_id"] = $itinerary["itinerary_id"];
                $tmp["driver_id"] = $itinerary["driver_id"];
                $tmp["customer_id"] = $itinerary["customer_id"];
                $tmp["start_address"] = $itinerary["start_address"];
                $tmp["start_address_lat"] = $itinerary["start_address_lat"];
                $tmp["start_address_long"] = $itinerary["start_address_long"];
                $tmp["pick_up_address"] = $itinerary["pick_up_address"];
                $tmp["pick_up_address_lat"] = $itinerary["pick_up_address_lat"];
                $tmp["pick_up_address_long"] = $itinerary["pick_up_address_long"];
                $tmp["drop_address"] = $itinerary["drop_address"];
                $tmp["drop_address_lat"] = $itinerary["drop_address_lat"];
                $tmp["drop_address_long"] = $itinerary["drop_address_long"];
                $tmp["end_address"] = $itinerary["end_address"];
                $tmp["end_address_lat"] = $itinerary["end_address_lat"];
                $tmp["end_address_long"] = $itinerary["end_address_long"];
                $tmp["leave_date"] = $itinerary["leave_date"];
                $tmp["duration"] = $itinerary["duration"];
                $tmp["distance"] = $itinerary["distance"];
                $tmp["cost"] = $itinerary["cost"];
                $tmp["description"] = $itinerary["description"];
                $tmp["status"] = $itinerary["status"];
                $tmp["created_at"] = $itinerary["created_at"];

                //driver info
                $tmp["driver_license"] = $itinerary["driver_license"];
                $tmp["driver_license_img"] = $itinerary["driver_license_img"];
                
                //user info
                $tmp["user_id"] = $itinerary["user_id"];
                $tmp["email"] = $itinerary["email"];
                $tmp["fullname"] = $itinerary["fullname"];
                $tmp["phone"] = $itinerary["phone"];
                $tmp["personalID"] = $itinerary["personalID"];
                $tmp["link_avatar"] = $itinerary["link_avatar"];

                //rating
                $tmp["average_rating"] = $db->getAverageRatingofDriver($itinerary["user_id"]);
                array_push($response["itineraries"], $tmp);
            }

            //print_r($response);

            //echo $response;
            echoRespnse(200, $response);

        });


$app->get('staff/itinerary/:id', function($itinerary_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getItinerary($itinerary_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response["itinerary_id"] = $result["itinerary_id"];
                $response["driver_id"] = $result["driver_id"];
                $response["customer_id"] = $result["customer_id"];
                $response["start_address"] = $result["start_address"];
                $response["start_address_lat"] = $result["start_address_lat"];
                $response["start_address_long"] = $result["start_address_long"];
                $response["pick_up_address"] = $result["pick_up_address"];
                $response["pick_up_address_lat"] = $result["pick_up_address_lat"];
                $response["pick_up_address_long"] = $result["pick_up_address_long"];
                $response["drop_address"] = $result["drop_address"];
                $response["drop_address_lat"] = $result["drop_address_lat"];
                $response["drop_address_long"] = $result["drop_address_long"];
                $response["end_address"] = $result["end_address"];
                $response["end_address_lat"] = $result["end_address_lat"];
                $response["end_address_long"] = $result["end_address_long"];
                $response["leave_date"] = $result["leave_date"];
                $response["duration"] = $result["duration"];
                $response["distance"] = $result["distance"];
                $response["cost"] = $result["cost"];
                $response["description"] = $result["description"];
                $response["status"] = $result["status"];
                $response["created_at"] = $result["created_at"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_REQUEST_ITINERARY'];
                echoRespnse(404, $response);
            }
        });

$app->put('staff/itinerary/:id', 'authenticateStaff', function($itinerary_id) use($app) {
            // check for required params
            //verifyRequiredParams(array('task', 'status'));
            global $staff_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $itinerary_fields = array();

            $request_params = array();
            $request_params = $_REQUEST;
            // Handling PUT request params
            if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
                $app = \Slim\Slim::getInstance();
                parse_str($app->request()->getBody(), $request_params);
            }

            $db = new DbHandler();
            $response = array();
            // updating task
            $result = $db->updateItinerary2($request_params, $itinerary_id);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = $lang['UPDATE_ITINERARY_SUCCESS'];
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['UPDATE_ITINERARY_FAILURE'];
            }
            echoRespnse(200, $response);
        });

$app->delete('/staff/itinerary/:id', function($itinerary_id) use($app) {
            //global $staff_id;
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteItinerary($itinerary_id);
            if ($result) {
                // itinerary deleted successfully
                $response["error"] = false;
                $response["message"] = $lang['DELETE_ITINERARY_SUCCESS'];
            } else {
                // itinerary failed to delete
                $response["error"] = true;
                $response["message"] = $lang['DELETE_ITINERARY_FAILURE'];
            }
            echoRespnse(200, $response);
        });

//Route itinerary
//
//
$app->post('/itinerary', 'authenticateUser', function() use ($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('start_address','start_address_lat','start_address_long','end_address',
                'end_address_lat','end_address_long','leave_date','duration','cost', 'distance'), $language);

            $response = array();
            
            $start_address = $app->request->post('start_address');
            $start_address_lat = $app->request->post('start_address_lat');
            $start_address_long = $app->request->post('start_address_long');
            $end_address = $app->request->post('end_address');
            $end_address_lat = $app->request->post('end_address_lat');
            $end_address_long = $app->request->post('end_address_long');
            $pick_up_address = $app->request->post('pick_up_address');
            $pick_up_address_lat = $app->request->post('pick_up_address_lat');
            $pick_up_address_long = $app->request->post('pick_up_address_long');
            $drop_address = $app->request->post('drop_address');
            $drop_address_lat = $app->request->post('drop_address_lat');
            $drop_address_long = $app->request->post('drop_address_long');
            $leave_date = $app->request->post('leave_date');
            $duration = $app->request->post('duration');
            $cost = $app->request->post('cost');
            $description = $app->request->post('description');
            $distance = $app->request->post('distance');

            //echo $start_address;

            global $user_id;
            $db = new DbHandler();

            // creating new itinerary
            $itinerary_id = $db->createItinerary($user_id, $start_address, $start_address_lat,$start_address_long,
             $end_address, $end_address_lat, $end_address_long, $pick_up_address, $pick_up_address_lat, $pick_up_address_long,
             $drop_address, $drop_address_lat, $drop_address_long, $leave_date, $duration, $cost, $description, $distance);

            if ($itinerary_id != NULL) {
                $response["error"] = false;
                $response["message"] = $lang['CREATE_ITINERARY_SUCCESS'];
                $response["itinerary_id"] = $itinerary_id;
                echoRespnse(201, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['CREATE_ITINERARY_FAILURE'];
                echoRespnse(200, $response);
            }            
        });

/**
 * Listing single task of particual user
 * method GET
 * url /tasks/:id
 * Will return 404 if the task doesn't belongs to user
 */
$app->get('/itinerary/:id', function($itinerary_id) {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getItinerary($itinerary_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response["itinerary_id"] = $result["itinerary_id"];
                $response["driver_id"] = $result["driver_id"];
                $response["customer_id"] = $result["customer_id"];
                $response["start_address"] = $result["start_address"];
                $response["start_address_lat"] = $result["start_address_lat"];
                $response["start_address_long"] = $result["start_address_long"];
                $response["pick_up_address"] = $result["pick_up_address"];
                $response["pick_up_address_lat"] = $result["pick_up_address_lat"];
                $response["pick_up_address_long"] = $result["pick_up_address_long"];
                $response["drop_address"] = $result["drop_address"];
                $response["drop_address_lat"] = $result["drop_address_lat"];
                $response["drop_address_long"] = $result["drop_address_long"];
                $response["end_address"] = $result["end_address"];
                $response["end_address_lat"] = $result["end_address_lat"];
                $response["end_address_long"] = $result["end_address_long"];
                $response["leave_date"] = $result["leave_date"];
                $response["duration"] = $result["duration"];
                $response["distance"] = $result["distance"];
                $response["cost"] = $result["cost"];
                $response["description"] = $result["description"];
                $response["status"] = $result["status"];
                $response["created_at"] = $result["created_at"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

/**
 * Listing all itineraries of particual user
 * method GET
 * url /itineraries          
 */
$app->get('/itineraries', 'authenticateUser', function() use($app) {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            $start_address = $app->request->get('start_address');
            $start_address_lat = $app->request->get('start_address_lat');
            $start_address_long = $app->request->get('start_address_long');

            $end_address = $app->request->get('end_address');
            $end_address_lat = $app->request->get('end_address_lat');
            $end_address_long = $app->request->get('end_address_long');

            $leave_date = $app->request->get('leave_date');
            $duration = $app->request->get('duration');
            $cost = $app->request->get('cost');
            $distance = $app->request->get('distance');

            echo $start_address;

            if (isset($start_address) || isset($end_address)) {
                $result = $db->searchItineraries($start_address, $end_address);
            } else {
                // fetching all user tasks
                $result = $db->getAllItinerariesWithDriverInfo();
            }
            $response["error"] = false;
            $response["itineraries"] = $result;

            echoRespnse(200, $response);

        });

/**
 * Listing all itineraries of driver
 * method GET
 * url /itineraries          
 */
$app->get('/itineraries/driver/:order', 'authenticateUser', function($order) {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetching all user tasks
            $result = $db->getDriverItineraries($user_id, $order);

            $response["error"] = false;
            $response["itineraries"] = array();

            //print_r($result);

            // looping through result and preparing tasks array
            while ($itinerary = $result->fetch_assoc()) {
                $tmp = array();
                //itinerary info
                $tmp["itinerary_id"] = $itinerary["itinerary_id"];
                $tmp["driver_id"] = $itinerary["driver_id"];
                $tmp["customer_id"] = $itinerary["customer_id"];
                $tmp["start_address"] = $itinerary["start_address"];
                $tmp["start_address_lat"] = $itinerary["start_address_lat"];
                $tmp["start_address_long"] = $itinerary["start_address_long"];
                $tmp["pick_up_address"] = $itinerary["pick_up_address"];
                $tmp["pick_up_address_lat"] = $itinerary["pick_up_address_lat"];
                $tmp["pick_up_address_long"] = $itinerary["pick_up_address_long"];
                $tmp["drop_address"] = $itinerary["drop_address"];
                $tmp["drop_address_lat"] = $itinerary["drop_address_lat"];
                $tmp["drop_address_long"] = $itinerary["drop_address_long"];
                $tmp["end_address"] = $itinerary["end_address"];
                $tmp["end_address_lat"] = $itinerary["end_address_lat"];
                $tmp["end_address_long"] = $itinerary["end_address_long"];
                $tmp["leave_date"] = $itinerary["leave_date"];
                $tmp["duration"] = $itinerary["duration"];
                $tmp["distance"] = $itinerary["distance"];
                $tmp["cost"] = $itinerary["cost"];
                $tmp["description"] = $itinerary["description"];
                $tmp["status"] = $itinerary["itinerary_status"];
                $tmp["created_at"] = $itinerary["created_at"];

                //driver info
                $tmp["driver_license"] = $itinerary["driver_license"];
                $tmp["driver_license_img"] = $itinerary["driver_license_img"];
                
                //user info
                $tmp["user_id"] = $itinerary["user_id"];
                $tmp["email"] = $itinerary["email"];
                $tmp["fullname"] = $itinerary["fullname"];
                $tmp["phone"] = $itinerary["phone"];
                $tmp["personalID"] = $itinerary["personalID"];
                $tmp["link_avatar"] = $itinerary["link_avatar"];
                array_push($response["itineraries"], $tmp);
                //print_r($itinerary);
                //echoRespnse(200, $itinerary);
            }           
            //print_r($response);
            echoRespnse(200, $response);
        });
/**
 * Listing all itineraries of customer
 * method GET
 * url /itineraries          
 */
$app->get('/itineraries/customer/:order', 'authenticateUser', function($order) {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetching all user tasks
            $result = $db->getCustomerItineraries($user_id, $order);

            $response["error"] = false;
            $response["itineraries"] = array();

            // looping through result and preparing tasks array
            while ($itinerary = $result->fetch_assoc()) {
                $tmp = array();
                //itinerary info
                $tmp["itinerary_id"] = $itinerary["itinerary_id"];
                $tmp["driver_id"] = $itinerary["driver_id"];
                $tmp["customer_id"] = $itinerary["customer_id"];
                $tmp["start_address"] = $itinerary["start_address"];
                $tmp["start_address_lat"] = $itinerary["start_address_lat"];
                $tmp["start_address_long"] = $itinerary["start_address_long"];
                $tmp["pick_up_address"] = $itinerary["pick_up_address"];
                $tmp["pick_up_address_lat"] = $itinerary["pick_up_address_lat"];
                $tmp["pick_up_address_long"] = $itinerary["pick_up_address_long"];
                $tmp["drop_address"] = $itinerary["drop_address"];
                $tmp["drop_address_lat"] = $itinerary["drop_address_lat"];
                $tmp["drop_address_long"] = $itinerary["drop_address_long"];
                $tmp["end_address"] = $itinerary["end_address"];
                $tmp["end_address_lat"] = $itinerary["end_address_lat"];
                $tmp["end_address_long"] = $itinerary["end_address_long"];
                $tmp["leave_date"] = $itinerary["leave_date"];
                $tmp["duration"] = $itinerary["duration"];
                $tmp["distance"] = $itinerary["distance"];
                $tmp["cost"] = $itinerary["cost"];
                $tmp["description"] = $itinerary["description"];
                $tmp["status"] = $itinerary["itinerary_status"];
                $tmp["created_at"] = $itinerary["created_at"];

                //driver info
                $tmp["driver_license"] = $itinerary["driver_license"];
                $tmp["driver_license_img"] = $itinerary["driver_license_img"];
                
                //user info
                $tmp["user_id"] = $itinerary["user_id"];
                $tmp["email"] = $itinerary["email"];
                $tmp["fullname"] = $itinerary["fullname"];
                $tmp["phone"] = $itinerary["phone"];
                $tmp["personalID"] = $itinerary["personalID"];
                $tmp["link_avatar"] = $itinerary["link_avatar"];
                array_push($response["itineraries"], $tmp);
                //print_r($itinerary);
                //echoRespnse(200, $itinerary);
            }           

            //print_r($response);
            echoRespnse(200, $response);
        });

//not finished yet: updated when accepted
/**
 * Updating existing itinerary
 * method PUT
 * params task, status
 * url - /itinerary/:id
 */
$app->put('/itinerary/:id', 'authenticateUser', function($itinerary_id) use($app) {
            // check for required params
            //verifyRequiredParams(array('task', 'status'));
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $itinerary_fields = array();           

            $request_params = array();
            $request_params = $_REQUEST;
            // Handling PUT request params
            if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
                $app = \Slim\Slim::getInstance();
                parse_str($app->request()->getBody(), $request_params);
            }

            $db = new DbHandler();
            $response = array();
            // updating task
            $result = $db->updateItinerary2($request_params, $itinerary_id);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = $lang['UPDATE_ITINERARY_SUCCESS'];
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['UPDATE_ITINERARY_FAILURE'];
            }
            echoRespnse(200, $response);
        });

/**
 * Updating when itinerary is accepted by customer
 * method PUT
 * params 
 * url - /accept_itinerary/:id
 */
$app->put('/customer_accept_itinerary/:id', 'authenticateUser', function($itinerary_id) use($app) {
            // check for required params
            //verifyRequiredParams(array('task', 'status'));

            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            //$itinerary_fields = array();           

            //$request_params = array();
            //$request_params = $_REQUEST;
            // Handling PUT request params
            /*if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
                $app = \Slim\Slim::getInstance();
                parse_str($app->request()->getBody(), $request_params);
            }*/

            $db = new DbHandler();
            $response = array();

            $status = $db->checkItineraryStatus($itinerary_id);
            
            if($status==1){
                // updating task
                $result = $db->updateCustomerAcceptedItinerary($itinerary_id, $user_id);
                if ($result) {
                    // task updated successfully
                    $response["error"] = false;
                    $response["message"] = $lang['CUS_ACCEPT_ITINERARY_SUCCESS'];
                } else {
                    // task failed to update
                    $response["error"] = true;
                    $response["message"] = $lang['CUS_ACCEPT_ITINERARY_FAILURE'];
                }
            } else {
                $response["error"] = true;
                $response["message"] = $lang['CUS_ACCEPT_ITINERARY_ALREADY'];
            }

            echoRespnse(200, $response);
        });

/**
 * Updating when itinerary is rejected by customer
 * method PUT
 * params 
 * url - /accept_itinerary/:id
 */
$app->put('/customer_reject_itinerary/:id', 'authenticateUser', function($itinerary_id) use($app) {
            // check for required params
            //verifyRequiredParams(array('task', 'status'));

            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();
            // updating task
            $result = $db->updateCustomerRejectedItinerary($itinerary_id);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = $lang['CUS_REJECT_ITINERARY_SUCCESS'];
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['CUS_REJECT_ITINERARY_FAILURE'];
            }
            echoRespnse(200, $response);
        });

/**
 * Updating when itinerary is accepted by driver
 * method PUT
 * params 
 * url - /accept_itinerary/:id
 */
$app->put('/driver_accept_itinerary/:id', 'authenticateUser', function($itinerary_id) use($app) {
            // check for required params
            //verifyRequiredParams(array('task', 'status'));

            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();
            // updating task
            $result = $db->updateDriverAcceptedItinerary($itinerary_id);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = $lang['DRI_ACCEPT_ITINERARY_SUCCESS'];
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['DRI_ACCEPT_ITINERARY_FAILURE'];
            }
            echoRespnse(200, $response);
        });

/**
 * Updating when itinerary is rejected by driver
 * method PUT
 * params 
 * url - /accept_itinerary/:id
 */
$app->put('/driver_reject_itinerary/:id', 'authenticateUser', function($itinerary_id) use($app) {
            // check for required params
            //verifyRequiredParams(array('task', 'status'));

            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();
            // updating task
            $result = $db->updateDrivereRectedItinerary($itinerary_id);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = $lang['DRI_REJECT_ITINERARY_SUCCESS'];
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['DRI_REJECT_ITINERARY_FAILURE'];
            }
            echoRespnse(200, $response);
        });
//not finished 
//not finished yet: bi phat sau khi delete khi da duoc accepted
/**
 * Deleting itinerary. Users can delete only their itineraries
 * method DELETE
 * url /itinerary
 */
$app->delete('/itinerary/:id', 'authenticateUser', function($itinerary_id) use($app) {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteItinerary($itinerary_id);
            if ($result) {
                // itinerary deleted successfully
                $response["error"] = false;
                $response["message"] = $lang['DELETE_ITINERARY_SUCCESS'];
            } else {
                // itinerary failed to delete
                $response["error"] = true;
                $response["message"] = $lang['DELETE_ITINERARY_FAILURE'];
            }
            echoRespnse(200, $response);
        });

$app->post('/feedback', function() use ($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('email', 'name', 'content'), $language);

            $response = array();

            // reading post params
            $email = $app->request->post('email');
            $name = $app->request->post('name');
            $content = $app->request->post('content');

            // validating email address
            validateEmail($email, $language);

            $db = new DbHandler();
            $res = $db->createFeedback($email, $name, $content);

            if ($res == USER_CREATED_FEEDBACK_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = $lang['ALERT_FEEDBACK'];
            } else if ($res == USER_CREATE_FEEDBACK_FAILED) {
                $response["error"] = true;
                $response["message"] = $lang['ERR_FEEDBACK'];
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->get('/comment/:user_id', 'authenticateUser', function($user_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                require_once '../include/lang_'.$_GET['lang'].'.php';
            } else {
                require_once '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            if ($db->isUserExists1($user_id)) {
                $response['error'] = false;
                $response['comments'] = array();
                $result = $db->getListCommentOfUser($user_id);
                while ($comment = $result->fetch_assoc()) {
                    array_push($response['comment'], $comment);
                }
                echoRespnse(200, $response);

            } else {
                $response['error'] = true;
                $response['message'] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields, $language) {
    if ($language != NULL) {
        include '../include/lang_'.$language.'.php';
    } else {
        include '../include/lang_en.php';
    }

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
        $response["message"] = $lang['ERR_MISSING_FIELD'] . substr($error_fields, 0, -2) . ' !';
        echoRespnse(200, $response);
        $app->stop();
    }
}

/**
 * Validating email address
 */
function validateEmail($email, $language) {
    if ($language != NULL) {
        include '../include/lang_'.$language.'.php';
    } else {
        include '../include/lang_en.php';
    }
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = $lang['ERR_EMAIL_VALID'];
        echoRespnse(200, $response);
        $app->stop();
    }
}

/**
 * Validating password
 */
function validatePassword($password, $language) {
    if ($language != NULL) {
        include '../include/lang_'.$language.'.php';
    } else {
        include '../include/lang_en.php';
    }
    $app = \Slim\Slim::getInstance();

    if ((strlen($password) < 6) || (strlen($password) > 12)) {

        $response["error"] = true;
        $response["message"] = $lang['ERR_PASS_LENGTH'];
        echoRespnse(200, $response);
        $app->stop();
    } 

    if (preg_match('#[\\s]#', $password)) {
        $response["error"] = true;
        $response["message"] = $lang['ERR_PASS_BLANKSPACE'];
        echoRespnse(200, $response);
        $app->stop();
    } 
}

/**
 * Send activation email
 */
function sendMail($receiver_mail, $content, $subject) {
    require_once '../libs/PHPMailer/class.phpmailer.php';

    $mail               = new PHPMailer();
    $body               = $content;
    $body               = eregi_replace("[\]",'',$body);
    $mail->IsSMTP();                            // telling the class to use SMTP

    $mail->SMTPAuth     = true;                  // enable SMTP authentication
    $mail->SMTPSecure   = "tls";                 // sets the prefix to the servier
    $mail->Host         = "smtp.gmail.com";      // sets GMAIL as the SMTP server
    $mail->Port         = 587;                   // set the SMTP port for the GMAIL server
    $mail->Username     = "thanhbkdn92@gmail.com";  // GMAIL username
    $mail->Password     = "thanhkdt123@";            // GMAIL password

    $mail->SetFrom('thanhbkdn92@gmail.com', 'Ride Sharing Verification Team'); //Sender

    $mail->Subject      = $subject; //Subject

    $mail->MsgHTML($body);

    $address = $receiver_mail; //Receiver
    $mail->AddAddress($address, "Guest"); //Send to?

    // $mail->AddAttachment("dinhkem/02.jpg");      // Attach
    // $mail->AddAttachment("dinhkem/200_100.jpg"); // Attach

    if(!$mail->Send()) {
      return false;
    } else {
      return true;
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