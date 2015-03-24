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
$restricted_user_field = array('user_id', 'email', 'api_key', 'created_at', 'status', 'personalID');


/**
 * Adding Middle Layer to authenticate User every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticateUser(\Slim\Route $route) {
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
            $response["message"] = "Access Denied.";
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
 * Adding Middle Layer to authenticate Staff every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticateStaff(\Slim\Route $route) {
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
            $response["message"] = "Access Denied. Invalid Api key";
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
                $user = $db->getUserByEmail($email);
                $activation_code = $user["api_key"];

                $content_mail = "Chào bạn,<br>
                                Vui lòng nhấn vào đường link sau để kích hoạt tài khoản:
                                <a href='http://localhost/RESTFul/v1/user/active". $activation_code.
                                "'>Kích hoạt tài khoản</a>";

                sendMail($email, $content_mail);

                $response["error"] = false;
                $response["message"] = "Đăng kí thành công. Vui lòng kích hoạt tài khoản qua email bạn vừa đăng kí!";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Xin lỗi! email bạn đăng kí đã tồn tại.";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Xin lỗi! Có lỗi xảy ra trong quá trình đăng kí.";
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
$app->get('/user/active/:activation_code', function($activation_code) {
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
$app->post('/user/login', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('email', 'password'));

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
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "Có lỗi xảy ra! Vui lòng thử lại.";
                }
            } elseif ($res == WRONG_PASSWORD || $res == USER_NOT_REGISTER) {
                $response['error'] = true;
                $response['message'] = "Sai email hoặc mật khẩu!";
            } elseif ($res == USER_NOT_ACTIVATE) {
                $response['error'] = true;
                $response['message'] = "Tài khoản chưa được kích hoạt. Vui lòng kích hoạt tài khoản!";
            } elseif($res == USER_LOCKED) {
                $response['error'] = true;
                $response['message'] = "Tài khoản của bạn đang bị khóa!";
            }
            else{
                $response['error'] = true;
                $response['message'] = "Có lỗi xảy ra trong quá trình đăng nhập!";
            }

            echoRespnse(200, $response);
        });

/**
 * Get user information
 * method GET
 * url /user
 */
$app->get('/user', 'authenticateUser', function() {
            global $user_id;
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
                $response["message"] = "Đường dẫn bạn yêu cầu không tồn tại!";
                echoRespnse(404, $response);
            }
        });

/**
 * Get user information
 * method GET
 * url /user
 */
$app->get('/user/:field', 'authenticateUser', function($field) {
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
                $response["message"] = "Đường dẫn bạn yêu cầu không tồn tại!";
                echoRespnse(404, $response);
            }
        });

/**
 * Updating user
 * method PUT
 * params task, status
 * url - /user
 */
$app->put('/user', 'authenticateUser', function() use($app) {
            // check for required params
            verifyRequiredParams(array('fullname', 'phone', 'personalID', 'personalID_img', 'link_avatar', 'locked'));

            global $user_id;            
            $fullname = $app->request->put('fullname');
            $phone = $app->request->put('phone');
            $personalID = $app->request->put('personalID');
            $personalID_img = $app->request->put('personalID_img');
            $link_avatar = $app->request->put('link_avatar');
            $locked = $app->request->put('locked');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateUser($user_id, $fullname, $phone, $personalID, $personalID_img, $link_avatar, $locked);
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
 * Update user information
 * method PUT
 * url /user
 */
$app->put('/user/:field', 'authenticateUser', function($field) use($app) {
            global $restricted_user_field;
            if (!in_array($field, $restricted_user_field)) {
                // check for required params
                verifyRequiredParams(array('value'));
                global $user_id;
                $value = $app->request->put('value');

                $response = array();
                $db = new DbHandler();

                if ($field == 'password') {
                    validatePassword($value);

                    $result = $db->changePassword($user_id, $value);
                } else {
                    // fetch user
                    $result = $db->updateUserField($user_id, $field, $value);
                }

                if ($result) {
                    // user updated successfully
                    $response["error"] = false;
                    $response["message"] = "Cập nhật thông tin thành công!";
                } else {
                    // user failed to update
                    $response["error"] = true;
                    $response["message"] = "Cập nhật thông tin thất bại. Vui lòng thử lại!";
                }
            } else {
                $response["error"] = true;
                $response["message"] = "Cập nhật thông tin thất bại. Vui lòng thử lại!";
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

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteUser($user_id);

            if ($result) {
                // user deleted successfully
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
 * Driver Registration
 * url - /driver
 * method - POST
 * params - driver
 */
$app->post('/driver', 'authenticateUser', function() use ($app) {
            global $user_id;

            $response = array();

            // reading post params
            $driver_license = $app->request->post('driver_license');
            $driver_license_img = $app->request->post('driver_license_img');

            $db = new DbHandler();
            $res = $db->createDriver($user_id, $driver_license, $driver_license_img);

            if ($res == DRIVER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "Đăng kí thành công!";
            } else if ($res == DRIVER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Bạn đã đăng kí làm lái xe!";
            } else if ($res == DRIVER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Xin lỗi! Có lỗi xảy ra trong quá trình đăng kí.";
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
                $response["message"] = "Đường dẫn bạn yêu cầu không tồn tại!";
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
                $response["message"] = "Đường dẫn bạn yêu cầu không tồn tại!";
                echoRespnse(404, $response);
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
            verifyRequiredParams(array('driver_license', 'driver_license_img'));

            global $user_id;            
            $driver_license = $app->request->put('driver_license');
            $driver_license_img = $app->request->put('driver_license_img');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateDriver($user_id, $driver_license, $driver_license_img);
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
 * Update user information
 * method PUT
 * url /user
 */
$app->put('/driver/:field', 'authenticateUser', function($field) use($app) {
            // check for required params
            verifyRequiredParams(array('value'));
            global $user_id;
            $value = $app->request->put('value');

            $response = array();
            $db = new DbHandler();

            // fetch user
            $result = $db->updateDriverField($user_id, $field, $value);

            if ($result) {
                // user updated successfully
                $response["error"] = false;
                $response["message"] = "Cập nhật thông tin thành công!";
            } else {
                // user failed to update
                $response["error"] = true;
                $response["message"] = "Cập nhật thông tin thất bại. Vui lòng thử lại!";
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

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteDriver($user_id);

            if ($result) {
                // user deleted successfully
                $response["error"] = false;
                $response["message"] = "Xóa tài xế thành công!";
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = "Xóa tài xế thất bại. Vui lòng thử lại!";
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
            // check for required params
            verifyRequiredParams(array('email'));

            $response = array();

            // reading post params
            $role = $app->request->post('role');
            $email = $app->request->post('email');
            $fullname = $app->request->post('fullname');
            $personalID = $app->request->post('personalID');

            // validating email address
            validateEmail($email);

            $db = new DbHandler();
            $res = $db->createStaff($role, $email, $fullname, $personalID);

            if ($res == STAFF_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "Tạo nhân viên mới thành công!";
            } else if ($res == STAFF_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Xin lỗi! email bạn đăng kí đã tồn tại.";
            } else if ($res == STAFF_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Xin lỗi! Có lỗi xảy ra trong quá trình đăng kí.";
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
            // check for required params
            verifyRequiredParams(array('email', 'password'));

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
                    $response['message'] = "Có lỗi xảy ra! Vui lòng thử lại.";
                }
            } elseif ($res == WRONG_PASSWORD || $res == STAFF_NOT_REGISTER) {
                $response['error'] = true;
                $response['message'] = "Sai email hoặc mật khẩu!";
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
                $response["message"] = "Đường dẫn bạn yêu cầu không tồn tại!";
                echoRespnse(404, $response);
            }
        });

/**
 * Get all user information
 * method GET
 * url /user
 */
$app->get('/staff/user', 'authenticateStaff', function() {
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
                $response["message"] = "Đường dẫn bạn yêu cầu không tồn tại!";
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
            // check for required params
            verifyRequiredParams(array('fullname', 'phone', 'personalID', 'personalID_img', 'link_avatar', 'locked'));
         
            $fullname = $app->request->put('fullname');
            $phone = $app->request->put('phone');
            $personalID = $app->request->put('personalID');
            $personalID_img = $app->request->put('personalID_img');
            $link_avatar = $app->request->put('link_avatar');
            $locked = $app->request->put('locked');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateUser($user_id, $fullname, $phone, $personalID, $personalID_img, $link_avatar, $locked);
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
 * Update user information
 * method PUT
 * url /user
 */
$app->put('/staff/user/:user_id/:field', 'authenticateStaff', function($user_id, $field) use($app) {
            global $restricted_user_field;

            if (!in_array($field, $restricted_user_field)) {
                // check for required params
                verifyRequiredParams(array('value'));

                $value = $app->request->put('value');

                $response = array();
                $db = new DbHandler();

                if ($field == 'password') {
                    validatePassword($value);

                    $result = $db->changePassword($user_id, $value);
                } else {
                    // fetch user
                    $result = $db->updateUserField($user_id, $field, $value);
                }

                if ($result) {
                    // user updated successfully
                    $response["error"] = false;
                    $response["message"] = "Cập nhật thông tin thành công!";
                } else {
                    // user failed to update
                    $response["error"] = true;
                    $response["message"] = "Cập nhật thông tin thất bại. Vui lòng thử lại!";
                }
            } else {
                $response["error"] = true;
                $response["message"] = "Cập nhật thông tin thất bại. Vui lòng thử lại!";
            }
            
            echoRespnse(200, $response);
        });

/**
 * Deleting user.
 * method DELETE
 * url /staff/user
 */
$app->delete('/staff/user/:user_id', 'authenticateStaff', function($user_id) {

            $db = new DbHandler();
            $response = array();

            $result = $db->deleteUser($user_id);

            if ($result) {
                // user deleted successfully
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
 * Listing single task of particual user
 * method GET
 * url /tasks/:id
 * Will return 404 if the task doesn't belongs to user
 */
$app->get('/itinerary/:id', function($itinerary_id) {
            global $user_id;
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
                $response["pick_up_address"] = $result["pick_up_address"];
                $response["drop_address"] = $result["drop_address"];
                $response["end_address"] = $result["end_address"];
                $response["leave_date"] = $result["leave_date"];
                $response["duration"] = $result["duration"];
                $response["cost"] = $result["cost"];
                $response["description"] = $result["description"];
                $response["status"] = $result["status"];
                $response["created_at"] = $result["created_at"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });

//Route itinerary
//
//
$app->post('/itinerary', 'authenticateUser', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('start_address','start_address_lat','start_address_long','end_address',
                'end_address_lat','end_address_long','leave_date','duration','cost'));

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

            //echo $start_address;

            global $user_id;
            $db = new DbHandler();

            // creating new itinerary
            $itinerary_id = $db->createItinerary($user_id, $start_address, $start_address_lat,$start_address_long,
             $end_address, $end_address_lat, $end_address_long, $pick_up_address, $pick_up_address_lat, $pick_up_address_long,
             $drop_address, $drop_address_lat, $drop_address_long, $leave_date, $duration, $cost, $description);

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
 * Listing single task of particual user
 * method GET
 * url /tasks/:id
 * Will return 404 if the task doesn't belongs to user
 */
$app->get('/itinerary/:id', function($itinerary_id) {
            global $user_id;
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
                $response["pick_up_address"] = $result["pick_up_address"];
                $response["drop_address"] = $result["drop_address"];
                $response["end_address"] = $result["end_address"];
                $response["leave_date"] = $result["leave_date"];
                $response["duration"] = $result["duration"];
                $response["cost"] = $result["cost"];
                $response["description"] = $result["description"];
                $response["status"] = $result["status"];
                $response["created_at"] = $result["created_at"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });

/**
 * Listing all itineraries of particual user
 * method GET
 * url /itineraries          
 */
$app->get('/itineraries', 'authenticateUser', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetching all user tasks
            $result = $db->getAllItineraries();

            $response["error"] = false;
            $response["itineraries"] = array();

            // looping through result and preparing tasks array
            while ($itinerary = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["itinerary_id"] = $itinerary["itinerary_id"];
                $tmp["driver_id"] = $itinerary["driver_id"];
                $tmp["customer_id"] = $itinerary["customer_id"];
                $tmp["start_address"] = $itinerary["start_address"];
                $tmp["pick_up_address"] = $itinerary["pick_up_address"];
                $tmp["drop_address"] = $itinerary["drop_address"];
                $tmp["end_address"] = $itinerary["end_address"];
                $tmp["leave_date"] = $itinerary["leave_date"];
                $tmp["duration"] = $itinerary["duration"];
                $tmp["cost"] = $itinerary["cost"];
                $tmp["description"] = $itinerary["description"];
                $tmp["status"] = $itinerary["status"];
                $tmp["created_at"] = $itinerary["created_at"];
                array_push($response["itineraries"], $tmp);
            }

            print_r($response);

            //echo $response;
            echoRespnse(200, $response);

        });

/**
 * Listing all itineraries of driver
 * method GET
 * url /itineraries          
 */
$app->get('/itineraries/driver/:driver_id', 'authenticateUser', function($driver_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetching all user tasks
            $result = $db->getDriverItineraries($driver_id);

            $response["error"] = false;
            $response["itineraries"] = array();

            print_r($car_id);

            // looping through result and preparing tasks array
            while ($itinerary = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["itinerary_id"] = $itinerary["itinerary_id"];
                $tmp["driver_id"] = $itinerary["driver_id"];
                $tmp["customer_id"] = $itinerary["customer_id"];
                $tmp["start_address"] = $itinerary["start_address"];
                $tmp["pick_up_address"] = $itinerary["pick_up_address"];
                $tmp["drop_address"] = $itinerary["drop_address"];
                $tmp["end_address"] = $itinerary["end_address"];
                $tmp["leave_date"] = $itinerary["leave_date"];
                $tmp["duration"] = $itinerary["duration"];
                $tmp["cost"] = $itinerary["cost"];
                $tmp["description"] = $itinerary["description"];
                $tmp["status"] = $itinerary["status"];
                $tmp["created_at"] = $itinerary["created_at"];
                array_push($response["itineraries"], $tmp);
            }

            print_r($response);

            echoRespnse(200, $response);
        });

/**
 * Listing all itineraries of driver
 * method GET
 * url /itineraries          
 */
$app->get('/itineraries/customer/:customer_id', 'authenticateUser', function($customer_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetching all user tasks
            $result = $db->getCustomerItineraries($customer_id);

            $response["error"] = false;
            $response["itineraries"] = array();

            // looping through result and preparing tasks array
            while ($itinerary = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["itinerary_id"] = $itinerary["itinerary_id"];
                $tmp["driver_id"] = $itinerary["driver_id"];
                $tmp["customer_id"] = $itinerary["customer_id"];
                $tmp["start_address"] = $itinerary["start_address"];
                $tmp["pick_up_address"] = $itinerary["pick_up_address"];
                $tmp["drop_address"] = $itinerary["drop_address"];
                $tmp["end_address"] = $itinerary["end_address"];
                $tmp["leave_date"] = $itinerary["leave_date"];
                $tmp["duration"] = $itinerary["duration"];
                $tmp["cost"] = $itinerary["cost"];
                $tmp["description"] = $itinerary["description"];
                $tmp["status"] = $itinerary["status"];
                $tmp["created_at"] = $itinerary["created_at"];
                array_push($response["itineraries"], $tmp);
            }

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
            $itinerary_fields = array();           
            
            /*$itinerary_fields['customer_id'] = $app->request->put('customer_id');
            $itinerary_fields['start_address'] = $app->request->put('start_address');
            $itinerary_fields['pick_up_address'] = $app->request->put('pick_up_address');
            $itinerary_fields['drop_address'] = $app->request->put('drop_address');
            $itinerary_fields['end_address'] = $app->request->put('end_address');
            $itinerary_fields['leave_date'] = $app->request->put('leave_date');
            $itinerary_fields['duration'] = $app->request->put('duration');
            $itinerary_fields['cost'] = $app->request->put('cost');
            $itinerary_fields['description'] = $app->request->put('description');
            $itinerary_fields['status'] = $app->request->put('status');
            $end_address = $app->request->post('end_address');
            $leave_day = $app->request->post('leave_day');
            $duration = $app->request->post('duration');
            $cost = $app->request->post('cost');
            $description = $app->request->post('description');*/

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
                $response["message"] = "Itinerary updated successfully";
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = "Itinerary failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

//not finished yet: bi phat sau khi delete khi da duoc accepted
/**
 * Deleting itinerary. Users can delete only their itineraries
 * method DELETE
 * url /itinerary
 */
$app->delete('/itinerary/:id', 'authenticateUser', function($itinerary_id) use($app) {
            global $user_id;

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteItinerary($itinerary_id);
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
        $response["message"] = 'Bạn chưa nhập ' . substr($error_fields, 0, -2) . ' !';
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
        $response["message"] = 'Email không hợp lệ!';
        echoRespnse(200, $response);
        $app->stop();
    }
}

/**
 * Validating password
 */
function validatePassword($password) {
    $app = \Slim\Slim::getInstance();

    if ((strlen($password) < 6) || (strlen($password) > 12)) {

        $response["error"] = true;
        $response["message"] = 'Độ dài mật khẩu phải nằm trong khoảng 6 đến 12 kí tự!';
        echoRespnse(200, $response);
        $app->stop();
    } 

    if (preg_match('#[\\s]#', $password)) {
        $response["error"] = true;
        $response["message"] = 'Mật khẩu không được có khoảng trống!';
        echoRespnse(200, $response);
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
    $mail->IsSMTP();                            // telling the class to use SMTP

    $mail->SMTPAuth     = true;                  // enable SMTP authentication
    $mail->SMTPSecure   = "tls";                 // sets the prefix to the servier
    $mail->Host         = "smtp.gmail.com";      // sets GMAIL as the SMTP server
    $mail->Port         = 587;                   // set the SMTP port for the GMAIL server
    $mail->Username     = "thanhbkdn92@gmail.com";  // GMAIL username
    $mail->Password     = "thanhkdt123";            // GMAIL password

    $mail->SetFrom('thanhbkdn92@gmail.com', 'Ride Sharing Verification Team'); //Sender

    $mail->Subject    = "Activate account"; //Subject

    $mail->MsgHTML($body);

    $address = $receiver_mail; //Receiver
    $mail->AddAddress($address, "Guest"); //Send to?

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