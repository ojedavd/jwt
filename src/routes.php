<?php
use Slim\Http\Request;
use Slim\Http\Response;
use \Firebase\JWT\JWT;

$app->post('/login', function (Request $request, Response $response, array $args) {
 
    $input = $request->getParsedBody();
    $sql = "SELECT * FROM users WHERE email= :email";
    $sth = $this->db->prepare($sql);
    $sth->bindParam("email", $input['email']);
    $sth->execute();
    $user = $sth->fetchObject();
 
    // verify email address.
    if(!$user) {
        return $this->response->withJson(['error' => true, 'message' => 'These credentials do not match our records.']);  
    }
 
    // verify password.
    if (!password_verify($input['password'],$user->password)) {
        return $this->response->withJson(['error' => true, 'message' => 'These credentials do not match our records.']);  
    }
 
    $settings = $this->get('settings'); // get settings array.
    
    $token = JWT::encode(['iat' => time(), 'exp' => time()+60, 'id' => $user->id, 'email' => $user->email], $settings['jwt']['secret'], "HS256");
 
    return $this->response->withJson(['token' => $token]);
 
});


$app->group('/api', function(\Slim\App $app) {
 
    $app->get('/user',function(Request $request, Response $response, array $args) {
        return $this->response->withJson($request->getAttribute('decoded_token_data'));

    });

    $app->get("/secure",  function ($request, $response, $args) {
 
        $data = ["status" => 1, 'msg' => "This route is secure!"];
     
        return $response->withStatus(200)
            ->withHeader("Content-Type", "application/json")
            ->write(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    });

});

$app->get("/not-secure",  function ($request, $response, $args) {
 
    $data = ["status" => 1, 'msg' => "No need of token to access me"];
 
    return $response->withStatus(200)
        ->withHeader("Content-Type", "application/json")
        ->write(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
});
