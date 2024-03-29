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
     * @OA\Get(
     *     tags={"Product"},
     *     path="/api/products/{id}",
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of the product",
     *         required=true,
     *         @OA\Schema(
     *             type="number",
     *             format="int64"
     *         )
     *     ),
     *     @OA\Response(response="200", description="Get Product by ID.")
     * )
     */
    public function getById($id)
    {
        $product = Product::with('category')->with("product_images")->find($id);

        if (!$product) {
            return response()->json(['error' => 'Product not found'], 404);
        }

        return response()->json($product, 200, [
            'Content-Type' => 'application/json;charset=UTF-8',
            'Charset' => 'utf-8'
        ], JSON_UNESCAPED_UNICODE);
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

    /**
     * @OA\Post(
     *     tags={"Product"},
     *     path="/api/products/{id}",
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of the product",
     *         required=true,
     *         @OA\Schema(
     *             type="number",
     *             format="int64"
     *         )
     *     ),
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"category_id","name","price","quantity","description"},
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
     *     @OA\Response(response="200", description="Update Product.")
     * )
     */
    public function edit(Request $request, $id)
    {
        $input = $request->all();

        $validator = Validator::make($input, [
            "category_id" => "required",
            "name" => "required",
            "price" => "required",
            "description" => "required",
            "quantity" => "required",
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $product = Product::findOrFail($id);

        if (!$product) {
            return response()->json(['error' => 'Product not found'], 404);
        }

        // Update product details
        $product->update($input);

        // Update product images
        if ($request->hasFile("images")) {
            $manager = new ImageManager(new Driver());
            $folderName = "upload";
            $folderPath = public_path($folderName);

            $product_images = $product->product_images;
            $this->deteleExistedImages($product_images);

            //Add new images
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
        }

        $product->load('product_images');

        return response()->json($product, 200, [
            'Content-Type' => 'application/json;charset=UTF-8',
            'Charset' => 'utf-8'
        ], JSON_UNESCAPED_UNICODE);
    }

    /**
     * @OA\Delete(
     *     path="/api/products/{id}",
     *     tags={"Product"},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of the product",
     *         required=true,
     *         @OA\Schema(
     *             type="number",
     *             format="int64"
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Successfully delete product"
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Product not found"
     *     )
     * )
     */
    public function delete($id)
    {
        $product = Product::findOrFail($id);

        if (!$product) {
            return response()->json(['error' => 'Product not found'], 404);
        }

        $product_images = $product->product_images;
        $this->deteleExistedImages($product_images);

        $product->delete();

        return response()->json(['message' => 'Product deleted successfully']);
    }

    private function deteleExistedImages($product_images)
    {
        $folderName = "upload";

        foreach ($product_images as $image) {
            foreach ([50, 150, 300, 600, 1200] as $size) {
                $imagePath = public_path($folderName . '/' . $size . '_' . $image->name);
                if (file_exists($imagePath)) {
                    unlink($imagePath);
                }
            }
            $image->delete();
        }
    }
}
