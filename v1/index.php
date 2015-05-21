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
        include '../include/lang_'.$_GET['lang'].'.php';
    } else {
        $language = 'en';
        include '../include/lang_en.php';
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
        include '../include/lang_'.$_GET['lang'].'.php';
    } else {
        $language = 'en';
        include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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

                $content_mail = $lang["MAIL_REGISTER"]. $activation_code.$lang['MAIL_REGISTER_ACTIVE_ACCOUNT'];

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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();

            $db = new DbHandler();

            if ($db->isUserExists($email)) {
                $res = $db->getUserByEmail($email);

                if (isset($res)) {
                    $content_mail = $lang['FORGOTPASS_MSG']. $res['api_key']. $lang['FORGOTPASS_MSG1'];

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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
 * Get user information
 * method GET
 * url /staff/user
 */
$app->get('/users/:user_id', 'authenticateUser', function($user_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
 * Get user's field information
 * method GET
 * url /user/:field (field is name of field want to get information)
 * header - Authorization: API Key
 */
$app->get('/user/:field', 'authenticateUser', function($field) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            verifyRequiredParams(array('driver_license', 'driver_license_img'), $language);

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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
            global $user_id;  

            $language = "en";

            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            } 

            // check for required params
            verifyRequiredParams(array('driver_license', 'driver_license_img'), $language); 

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
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('value'), $language);

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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
 * Vehicle Registration
 * url - /vehicle
 * method - POST
 * params - vehicle
 */
$app->post('/vehicle', 'authenticateUser', function() use ($app) {
            global $user_id;
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            verifyRequiredParams(array('type', 'license_plate', 
                                        'reg_certificate', 'license_plate_img', 'vehicle_img', 'motor_insurance_img'), $language);

            $response = array();

            $type = $app->request->post('type');
            $license_plate = $app->request->post('license_plate');
            $license_plate_img = $app->request->post('license_plate_img');
            $reg_certificate = $app->request->post('reg_certificate');
            $vehicle_img = $app->request->post('vehicle_img');
            $motor_insurance_img = $app->request->post('motor_insurance_img');

            $db = new DbHandler();
            $res = $db->createVehicle($user_id, $type, $license_plate, $license_plate_img, $reg_certificate,
                                        $vehicle_img, $motor_insurance_img);

            if ($res == VEHICLE_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = $lang['REGISTER_SUCCESS'];
            } else if ($res == VEHICLE_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = $lang['REGISTER_VEHICLE'];
            } else if ($res == VEHICLE_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = $lang['ERR_REGISTER'];
            }
            // echo json response
            echoRespnse(201, $response);
        });

$app->get('/vehicles', 'authenticateUser', function() {
            global $user_id;

            $db = new DbHandler();

            // fetch task
            $result = $db->getListVehicle($user_id);

            if ($result != NULL) {
                $response['error'] = false;
                $response['vehicles'] = array();

                while ($vehicle = $result->fetch_assoc()) {
                    array_push($response['vehicles'], $vehicle);               
                }

                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

/**
 * Get driver information
 * method GET
 * url /driver
 */
$app->get('/vehicle/:vehicle_id', 'authenticateUser', function($vehicle_id) {

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $vehicle = $db->getVehicle($vehicle_id);

            if ($vehicle != NULL) {
                $response["error"] = false;
                $response['vehicle_id'] = $vehicle["vehicle_id"];
                $response['user_id'] = $vehicle["user_id"];
                $response['type'] = $vehicle["type"];
                $response['license_plate'] = $vehicle["license_plate"];
                $response['reg_certificate'] = $vehicle["reg_certificate"];
                $response['license_plate_img'] = $vehicle["license_plate_img"];
                $response['vehicle_img'] = $vehicle["vehicle_img"];
                $response['motor_insurance_img'] = $vehicle["motor_insurance_img"];
                $response['status'] = $vehicle["status"];
                $response['created_at'] = $vehicle["created_at"];
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
$app->put('/vehicle/:vehicle_id', 'authenticateUser', function($vehicle_id) use($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }  

            $type = $app->request->put('type');
            $license_plate = $app->request->put('license_plate');
            $reg_certificate = $app->request->put('reg_certificate');
            $license_plate_img = $app->request->put('license_plate_img');
            $vehicle_img = $app->request->put('vehicle_img');
            $motor_insurance_img = $app->request->put('motor_insurance_img');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateVehicle($vehicle_id, $type, $license_plate, $reg_certificate, $license_plate_img, $vehicle_img, $motor_insurance_img);
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
 * Deleting user.
 * method DELETE
 * url /user
 */
$app->delete('/vehicle/:vehicle_id', 'authenticateUser', function($vehicle_id) {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteVehicle($vehicle_id);

            if ($result) {
                // user deleted successfully
                $response["error"] = false;
                $response["message"] = $lang['VEHICLE_DELETE_SUCCESS'];
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = $lang['VEHICLE_DELETE_FAILURE'];
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('start_address','start_address_lat','start_address_long','end_address',
                'end_address_lat','end_address_long','leave_date','duration','cost', 'distance', 'vehicle_id'), $language);

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
            $vehicle_id = $app->request->post('vehicle_id');

            global $user_id;
            $db = new DbHandler();

            $table = "";
            $itinerary = NULL;

            if (($end_address_lat - $start_address_lat) > 0.05 && ($end_address_long - $start_address_long) > 0.05) {
                $table = "itinerary_created_northeast";
            } else if (($end_address_lat - $start_address_lat) > 0.05 && ($end_address_long - $start_address_long) < -0.05) {
                $table = "itinerary_created_northwest";
            } else if (($end_address_lat - $start_address_lat) < -0.05 && ($end_address_long - $start_address_long) < -0.05) {
                $table = "itinerary_created_southwest";
            } else if (($end_address_lat - $start_address_lat) < -0.05 && ($end_address_long - $start_address_long) > 0.05) {
                $table = "itinerary_created_southeast";
            } else if (($end_address_lat - $start_address_lat) > -0.05 && ($end_address_lat - $start_address_lat) < 0.05 &&
                        ($end_address_long - $start_address_long) > 0.05) {
                $table = "itinerary_created_east";
            } else if (($end_address_lat - $start_address_lat) > -0.05 && ($end_address_lat - $start_address_lat) < 0.05 &&
                        ($end_address_long - $start_address_long) < -0.05) {
                $table = "itinerary_created_west";
            } else if (($end_address_long - $start_address_long) > -0.05 && ($end_address_long - $start_address_long) < 0.05 &&
                        ($end_address_lat - $start_address_lat) > 0.05) {
                $table = "itinerary_created_north";
            } else if (($end_address_long - $start_address_long) > -0.05 && ($end_address_long - $start_address_long) < 0.05 &&
                        ($end_address_lat - $start_address_lat) < -0.05) {
                $table = "itinerary_created_south";
            } else {
                $response["error"] = true;
                $response["message"] = $lang['CREATE_ITINERARY_FAILURE_BECAUSE_SHORT_DISTANCE'];
                echoRespnse(200, $response);
                $app->stop();
            }

            // creating new itinerary
            $itinerary_id = $db->createItinerary($user_id, $start_address, $start_address_lat,$start_address_long,
                     $end_address, $end_address_lat, $end_address_long, $pick_up_address, $pick_up_address_lat, $pick_up_address_long,
                     $drop_address, $drop_address_lat, $drop_address_long, $leave_date, $duration, $cost, $description, $distance, $vehicle_id, $table);

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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getItinerary($itinerary_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response["itinerary_id"] = $result["itinerary_id"];
                $response["driver_id"] = $result["driver_id"];
                $response["average_rating"] = $result["average_rating"];
                $response["vehicle_id"] = $result["vehicle_id"];
                $response["vehicle_type"] = $result["vehicle_type"];
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
                $response["phone"] = $result["phone"];
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            $start_address_lat = $app->request->get('start_address_lat');
            $start_address_long = $app->request->get('start_address_long');

            $end_address_lat = $app->request->get('end_address_lat');
            $end_address_long = $app->request->get('end_address_long');

            $leave_date = $app->request->get('leave_date');
            $duration = $app->request->get('duration');
            $cost = $app->request->get('cost');
            $distance = $app->request->get('distance');

            $startRow = 0;
            $endRow = 30;

            if (isset($start_address_lat) && isset($start_address_long) && isset($end_address_lat) && isset($end_address_long)) {
                $table = "";
                if (($end_address_lat - $start_address_lat) > 0.05 && ($end_address_long - $start_address_long) > 0.05) {
                    $table = "itinerary_created_northeast";
                    $result = $db->searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow);
                    if (count($result) < 30) {
                        
                    }
                } else if (($end_address_lat - $start_address_lat) > 0.05 && ($end_address_long - $start_address_long) < -0.05) {
                    $table = "itinerary_created_northwest";
                    $result = $db->searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow);
                } else if (($end_address_lat - $start_address_lat) < -0.05 && ($end_address_long - $start_address_long) < -0.05) {
                    $table = "itinerary_created_southwest";
                    $result = $db->searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow);
                } else if (($end_address_lat - $start_address_lat) < -0.05 && ($end_address_long - $start_address_long) > 0.05) {
                    $table = "itinerary_created_southeast";
                    $result = $db->searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow);
                } else if (($end_address_lat - $start_address_lat) > -0.05 && ($end_address_lat - $start_address_lat) < 0.05 &&
                            ($end_address_long - $start_address_long) > 0.05) {
                    $table = "itinerary_created_east";
                    $result = $db->searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow);

                    if (count($result) < 30) {
                        
                    }
                } else if (($end_address_lat - $start_address_lat) > -0.05 && ($end_address_lat - $start_address_lat) < 0.05 &&
                            ($end_address_long - $start_address_long) < -0.05) {
                    $table = "itinerary_created_west";
                    $result = $db->searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow);

                    if (count($result) < 30) {
                        
                    }
                } else if (($end_address_long - $start_address_long) > -0.05 && ($end_address_long - $start_address_long) < 0.05 &&
                            ($end_address_lat - $start_address_lat) > 0.05) {
                    $table = "itinerary_created_north";
                    $result = $db->searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow);

                    if (count($result) < 30) {
                        
                    }
                } else if (($end_address_long - $start_address_long) > -0.05 && ($end_address_long - $start_address_long) < 0.05 &&
                            ($end_address_lat - $start_address_lat) < -0.05) {
                    $table = "itinerary_created_south";
                    $result = $db->searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow);

                    if (count($result) < 30) {
                        
                    }
                } else {
                    $response["error"] = true;
                    $response["message"] = $lang['CREATE_ITINERARY_FAILURE_BECAUSE_SHORT_DISTANCE'];
                    echoRespnse(200, $response);
                    $app->stop();
                }
            } else if (isset($start_address_lat) && isset($start_address_long)) {
                $table = "AllStart";
                $result = $db->searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow);
            } else if (isset($end_address_lat) && isset($end_address_long)) {
                $table = "AllEnd";
                $result = $db->searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow);
            } else {
                // fetching all user tasks
                $result = $db->getAllItinerariesWithDriverInfo($user_id);
            }

            if (isset($result)) {
                $response["error"] = false;
                $response["itineraries"] = $result;
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(200, $response);
            } 
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                $tmp["vehicle_id"] = $itinerary["vehicle_id"];
                $tmp["vehicle_type"] = $itinerary["vehicle_type"];
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
            }           
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                $tmp["vehicle_id"] = $itinerary["vehicle_id"];
                $tmp["vehicle_type"] = $itinerary["vehicle_type"];
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $status = $db->checkItineraryStatus($itinerary_id);

            if ($status == 2 || $status == 3) {
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
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['CUS_REJECT_ITINERARY_FAILURE'];
                echoRespnse(200, $response);
            }
        });

$app->put('/customer_end_itinerary/:id', 'authenticateUser', function($itinerary_id) use($app) {
            // check for required params
            //verifyRequiredParams(array('task', 'status'));

            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $status = $db->checkItineraryStatus($itinerary_id);

            if ($status == 3) {
                // updating task
                $result = $db->updateCustomerEndItinerary($itinerary_id);
                if ($result) {
                    // task updated successfully
                    $response["error"] = false;
                    $response["message"] = $lang['CUS_END_ITINERARY_SUCCESS'];
                } else {
                    // task failed to update
                    $response["error"] = true;
                    $response["message"] = $lang['CUS_END_ITINERARY_FAILURE'];
                }
                echoRespnse(200, $response);
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['CUS_END_ITINERARY_FAILURE'];
                echoRespnse(200, $response);
            }
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $status = $db->checkItineraryStatus($itinerary_id);

            if ($status == 2) {
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
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['DRI_ACCEPT_ITINERARY_FAILURE'];
                echoRespnse(200, $response);
            }
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $status = $db->checkItineraryStatus($itinerary_id);

            if ($status == 2 || $status == 3) {
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
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['DRI_REJECT_ITINERARY_FAILURE'];
                echoRespnse(200, $response);
            }
        });
///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * Updating when itinerary ongoing
 * method PUT
 * params 
 * url - /accept_itinerary/:id
 */
$app->put('/driver_ongoing_itinerary/:id', 'authenticateUser', function($itinerary_id) use($app) {
            // check for required params
            //verifyRequiredParams(array('task', 'status'));

            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $status = $db->checkItineraryStatus($itinerary_id);

            if ($status == 2 || $status == 3) {
                // updating task
                $result = $db->updateOnGoingItinerary($itinerary_id);
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
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = $lang['DRI_REJECT_ITINERARY_FAILURE'];
                echoRespnse(200, $response);
            }
        });
///////////////////////////////////////////////////////////////////////////////////////////
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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


/////////////////////////////////////////////////////////////////////////////////



$app->get('/commentsofuser/:user_id', 'authenticateUser', function($user_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            if ($db->isUserExists1($user_id)) {
                $response['error'] = false;
                $response['comments'] = array();
                $result = $db->getListCommentOfUser($user_id);
                while ($comment = $result->fetch_assoc()) {
                    array_push($response['comments'], $comment);
                }
                echoRespnse(200, $response);

            } else {
                $response['error'] = true;
                $response['message'] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

$app->get('/commentsaboutuser/:user_id', 'authenticateUser', function($user_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            if ($db->isUserExists1($user_id)) {
                $response['error'] = false;
                $response['comments'] = array();
                $result = $db->getListCommentAboutUser($user_id);
                while ($comment = $result->fetch_assoc()) {
                    array_push($response['comments'], $comment);
                }
                echoRespnse(200, $response);

            } else {
                $response['error'] = true;
                $response['message'] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

/**
 * Comment creation
 * url - /comment
 * method - POST
 * params - 
 */
$app->post('/comment', 'authenticateUser', function() use ($app) {
            global $user_id;
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            verifyRequiredParams(array('content', 'comment_about_user_id'), $language);

            $response = array();

            $content = $app->request->post('content');
            $comment_about_user_id = $app->request->post('comment_about_user_id');

            $db = new DbHandler();
            $res = $db->createComment($user_id, $content, $comment_about_user_id);

            if ($res == COMMENT_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = $lang['RATING_SUCCESS'];
            } else if ($res == COMMENT_CREATE_FAILED) {
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
$app->get('/comment/:comment_id', 'authenticateUser', function($comment_id) {

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $comment = $db->getComment($comment_id);

            if ($comment != NULL) {
                $response["error"] = false;
                $response['comment_id'] = $comment["comment_id"];
                $response['comment_about_user_id'] = $comment["comment_about_user_id"];
                $response['content'] = $comment["content"];
                $response['created_at'] = $comment["created_at"];
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
$app->put('/comment/:comment_id', 'authenticateUser', function($comment_id) use($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }  

            $content = $app->request->post('content');
            $comment_about_user_id = $app->request->post('comment_about_user_id');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateComment($comment_id, $content);
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
 * Deleting user.
 * method DELETE
 * url /user
 */
$app->delete('/comment/:comment_id', 'authenticateUser', function($comment_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteComment($comment_id);

            if ($result) {
                // user deleted successfully
                $response["error"] = false;
                $response["message"] = $lang['VEHICLE_DELETE_SUCCESS'];
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = $lang['VEHICLE_DELETE_FAILURE'];
            }
            echoRespnse(200, $response);
        });


//////////////////////////////////////////////////////////////////////////////////////////
///statistic_customer/:field


$app->get('/rating/:user_id/:rating_user_id', 'authenticateUser', function($user_id, $rating_user_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            if ($db->isUserExists1($user_id)) {
                $response['error'] = false;
                $rating = $db->getRating($user_id, $rating_user_id);
                
                if ($rating != NULL) {
                    $response['rating'] = $rating["rating"];;
                    echoRespnse(200, $response);
                } else {
                    $response["message"] = $lang['ERR_LINK_REQUEST'];
                    echoRespnse(404, $response);
                }
                echoRespnse(200, $response);

            } else {
                $response['error'] = true;
                $response['message'] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

/**
 * Get driver information
 * method GET
 * url /driver
 */
$app->get('/average_rating/:user_id', 'authenticateUser', function($user_id) {

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $average_rating = $db->getAverageRatingofUser($user_id);

            if ($average_rating != NULL) {
                $response["error"] = false;
                $response['average_rating'] = $average_rating;
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });


/**
 * Comment creation
 * url - /comment
 * method - POST
 * params - 
 */
$app->post('/rating', 'authenticateUser', function() use ($app) {
            global $user_id;
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            verifyRequiredParams(array('rating', 'rating_user_id'), $language);

            $response = array();

            $rating = $app->request->post('rating');
            $rating_user_id = $app->request->post('rating_user_id');

            $db = new DbHandler();
            $res = $db->createRating($user_id, $rating, $rating_user_id);

            if ($res == RATING_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = $lang['RATING_SUCCESS'];
            } else if ($res == RATING_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = $lang['ERR_REGISTER'];
            }
            // echo json response
            echoRespnse(201, $response);
        });


/**
 * Deleting user.
 * method DELETE
 * url /user
 */
$app->delete('/rating/:rating_id', 'authenticateUser', function($rating_id) {
            global $user_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteRating($rating_id);

            if ($result) {
                // user deleted successfully
                $response["error"] = false;
                $response["message"] = $lang['VEHICLE_DELETE_SUCCESS'];
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = $lang['VEHICLE_DELETE_FAILURE'];
            }
            echoRespnse(200, $response);
        });




//Staticstic for admin
$app->get('/statistic/:field', 'authenticateStaff', function($field) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            if ($field == 'user'){
                $result = $db->statisticUserBy();
            } else if ($field == 'itinerary'){
                $result = $db->statisticItineraryBy();
            } else if ($field == 'total_money'){
                $result = $db->statisticMoneyBy();
            } else {

            }

            if (isset($result)) {
                $response['error'] = false;
                $response['stats'] = $result;

                echoRespnse(200, $response);

            } else {
                $response['error'] = true;
                $response['message'] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });


//staticstic for customer
$app->get('/statistic_customer/:year', 'authenticateUser', function( $year) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            global $user_id;

            $response = array();
            $db = new DbHandler();

            
            $result = $db->statisticCustomerBy($user_id, $year);
        
            //$result2 = $db->statisticCustomerMoneyBy($user_id, $year);
            

            if (isset($result)) {
                $response['error'] = false;
                $response['stats_customer'] = $result;
                //$response['stats_totalmoney'] = $result2;
                echoRespnse(200, $response);

            } else {
                $response['error'] = true;
                $response['message'] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
        });

$app->get('/statistic_driver/:year', 'authenticateUser', function( $year) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            global $user_id;

            $response = array();
            $db = new DbHandler();

            
            $result = $db->statisticDriverBy($user_id, $year);
        
            //$result2 = $db->statisticDriverMoneyBy($user_id, $year);
            

            if (isset($result)) {
                $response['error'] = false;
                $response['stats_driver'] = $result;
                //$response['stats_totalmoney'] = $result2;
                echoRespnse(200, $response);

            } else {
                $response['error'] = true;
                $response['message'] = $lang['ERR_LINK_REQUEST'];
                echoRespnse(404, $response);
            }
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                    $response['email'] = $staff['email'];
                    $response['fullname'] = $staff['fullname'];
                    $response['personalID'] = $staff['personalID'];
                    $response['created_at'] = $staff['created_at'];
                    $response['link_avatar'] = $staff['link_avatar'];
                    $response['staff_id'] = $staff['staff_id'];
                    $response['role'] = $staff['role'];
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

$app->get('/staffs/:staff_id', 'authenticateStaff', function($staff_id) {
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

$app->put('/staffs/:staff_id', 'authenticateStaff', function($staff_id) use($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }
        
            $fullname = $app->request->put('fullname');
            $email = $app->request->put('email');
            $personalID = $app->request->put('personalID');
            $link_avatar = $app->request->put('link_avatar');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateStaff($staff_id, $fullname, $email, $personalID, $link_avatar);
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
 * Deleting user.
 * method DELETE
 * url /staff/user
 */
$app->delete('/staffs/:staff_id', 'authenticateStaff', function($staff_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteStaff($staff_id);

            if ($result) {
                // user deleted successfully
                $response["error"] = false;
                $response["message"] = $lang['STAFF_DELETE_SUCCESS'];
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = $lang['STAFF_DELETE_FAILURE'];
            }
            echoRespnse(200, $response);
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
 * Get all user information
 * method GET
 * url /user
 */
$app->get('/staff/driver', 'authenticateStaff', function() {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            $response['error'] = false;
            $response['users'] = array();

            // fetch task
            $result = $db->getListDriver();

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
$app->get('/staff/driver/:user_id', 'authenticateStaff', function($user_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getDriverByUserID($user_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response['fullname'] = $result['fullname'];
                $response['driver_license'] = $result['driver_license'];
                $response['driver_license_img'] = $result['driver_license_img'];
                $response['created_at'] = $result['created_at'];
                $response['status'] = $result['status'];
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
$app->get('/staff/driver/:user_id/:field', 'authenticateStaff', function($user_id, $field) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                echoRespnse(404, $response);
            }
        });

/**
 * Updating user
 * method PUT
 * params task, status
 * url - /user
 */
$app->put('/staff/driver/:user_id', 'authenticateStaff', function($user_id) use($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('status'), $language);
        
            $status = $app->request->put('status');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateDriver1($user_id, $status);
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

$app->get('/staff/vehicle', 'authenticateStaff', function() {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            $response['error'] = false;
            $response['vehicles'] = array();

            // fetch task
            $result = $db->getListVehicles();

            while ($vehicle = $result->fetch_assoc()) {
                array_push($response['vehicles'], $vehicle);               
            }

            echoRespnse(200, $response);
        });

$app->get('/staff/vehicle/:vehicle_id', 'authenticateStaff', function($vehicle_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            $response['error'] = false;

            // fetch task
            $result = $db->getVehicle($vehicle_id);
            $response['vehicle'] = $result;

            echoRespnse(200, $response);
        });

$app->put('/staff/vehicle/:vehicle_id', 'authenticateStaff', function($vehicle_id) use($app) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            // check for required params
            verifyRequiredParams(array('status'), $language);
        
            $status = $app->request->put('status');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateVehicle1($vehicle_id, $status);
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


$app->get('/staff/feedback', 'authenticateStaff', function() {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();

            $response['error'] = false;
            $response['feedbacks'] = array();

            // fetch task
            $result = $db->getListFeedbacks();

            while ($feedback = $result->fetch_assoc()) {
                array_push($response['feedbacks'], $feedback);               
            }

            echoRespnse(200, $response);
        });

$app->delete('/staff/feedback/:feedback_id', 'authenticateStaff', function($feedback_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteFeedback($feedback_id);

            if ($result) {
                // user deleted successfully
                $response["error"] = false;
                $response["message"] = $lang['FEEDBACK_DELETE_SUCCESS'];
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = $lang['FEEDBACK_DELETE_FAILURE'];
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
            }

            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getAllItinerariesWithDriverInfo($staff_id);

            $response["error"] = false;
            $response["itineraries"] = $result;

            echoRespnse(200, $response);

        });


$app->get('/staff/itinerary/:id', function($itinerary_id) {
            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                $response["fullname"] = $result["fullname"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = $lang['ERR_REQUEST_ITINERARY'];
                echoRespnse(404, $response);
            }
        });

$app->put('/staff/itinerary/:id', 'authenticateStaff', function($itinerary_id) use($app) {
            // check for required params
            //verifyRequiredParams(array('task', 'status'));
            global $staff_id;

            $language = "en";
            if (isset($_GET['lang']) && file_exists('../include/lang_'.$_GET['lang'].'.php')) {
                $language = $_GET['lang'];
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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
                include '../include/lang_'.$_GET['lang'].'.php';
            } else {
                include '../include/lang_en.php';
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