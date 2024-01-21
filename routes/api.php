<?php

use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\CategoryController;
use App\Http\Controllers\API\ProductController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::get("categories", [CategoryController::class, 'getAll']);
Route::get('categories/{id}', [CategoryController::class, 'getById']);
Route::post("categories", [CategoryController::class, 'create']);
Route::post("categories/edit/{id}", [CategoryController::class, "edit"]);
Route::delete('categories/{id}', [CategoryController::class, 'delete']);

Route::post('register', [AuthController::class, 'register']);
Route::post('login', [AuthController::class, 'login']);

Route::get('products', [ProductController::class, 'getAll']);
Route::post('products', [ProductController::class, 'create']);