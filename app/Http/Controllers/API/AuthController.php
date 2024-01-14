<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Intervention\Image\Drivers\Gd\Driver;
use Intervention\Image\ImageManager;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    /**
     * @OA\Post(
     *     tags={"Auth"},
     *     path="/api/register",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"email", "lastName", "name", "phone", "image", "password", "password_confirmation"},
     *                 @OA\Property(
     *                     property="image",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="email",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="lastName",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="name",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="phone",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="password",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="password_confirmation",
     *                     type="string"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(response="200", description="Add Category.")
     * )
     */
    public function register(Request $request)
    {
        $input = $request->all();

        $validation = Validator::make($input, [
            "name" => "required|string",
            "lastName" => "required|string",
            "image" => "required|string",
            "phone" => "required|string",
            "email" => "required|email",
            "password" => "required|string",
        ]);

        if ($validation->fails()) {
            return response()->json($validation->errors(), Response::HTTP_BAD_REQUEST);
        }

        $imageName = uniqid() . ".webp";
        $sizes = [50, 150, 300, 600, 1200];


        $folderName = "upload";
        $folderPath = public_path($folderName);
        if (!file_exists($folderPath) && !is_dir($folderPath))
            mkdir($folderPath, 0777);

        $manager = new ImageManager(new Driver());

        foreach ($sizes as $size) {
            $imageSave = $manager->read($input["image"]);
            $imageSave->scale(width: $size);
            $imageSave->toWebp()->save($folderPath . "/" . $size . "_" . $imageName);
        }

        $user = User::create(
            array_merge(
                $validation->validated(),
                ['password' => bcrypt($input['password']), 'image' => $imageName]
            )
        );

        return response()->json(["user" => $user], Response::HTTP_OK);
    }
}