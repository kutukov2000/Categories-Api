<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Product;
use App\Models\ProductImage;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Intervention\Image\Drivers\Gd\Driver;
use Intervention\Image\ImageManager;

class ProductController extends Controller
{
    /**
     * @OA\Get(
     *     tags={"Product"},
     *     path="/api/products",
     *     @OA\Response(response="200", description="Products list.")
     * )
     */
    function getAll()
    {
        $list = Product::with('category')
            ->with("product_images")
            ->get();
        return response()->json($list)
            ->header('Content-Type', 'application/json; charset=utf-8');
    }
    /**
     * @OA\Post(
     *     tags={"Product"},
     *     path="/api/products",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"category_id","name","price","quantity","description","images[]"},
     *                 @OA\Property(
     *                     property="category_id",
     *                     type="integer"
     *                 ),
     *                 @OA\Property(
     *                     property="name",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="price",
     *                     type="number"
     *                 ),
     *                 @OA\Property(
     *                      property="quantity",
     *                      type="number"
     *                  ),
     *                 @OA\Property(
     *                     property="description",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="images[]",
     *                     type="array",
     *                     @OA\Items(type="string", format="binary")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(response="200", description="Add Product.")
     * )
     */
    public function create(Request $request)
    {
        $input = $request->all();

        $validator = Validator::make($input, [
            "category_id" => "required",
            "name" => "required",
            "price" => "required",
            "description" => "required",
            "quantity" => "required",
            "images" => "required",
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $product = Product::create($input);
        $manager = new ImageManager(new Driver());

        $folderName = "upload";
        $folderPath = public_path($folderName);

        if (!file_exists($folderPath) && !is_dir($folderPath))
            mkdir($folderPath, 0777);

        $sizes = [50, 150, 300, 600, 1200];
        $images = $request->file("images");
        foreach ($images as $image) {
            $imageName = uniqid() . ".webp";
            foreach ($sizes as $size) {
                $imageSave = $manager->read($image);
                $imageSave->scale(width: $size);
                $imageSave->toWebp()->save($folderPath . "/" . $size . "_" . $imageName);
            }
            ProductImage::create([
                'product_id' => $product->id,
                'name' => $imageName
            ]);
        }

        $product->load('product_images');

        return response()->json($product, 200, [
            'Content-Type' => 'application/json;charset=UTF-8',
            'Charset' => 'utf-8'
        ], JSON_UNESCAPED_UNICODE);
    }
}
