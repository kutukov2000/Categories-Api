<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Categories;
use Illuminate\Http\Request;

class CategoryController extends Controller
{
    function getAll() {
        $list = Categories::all();
        return response()->json($list,200, ['Charset'=>'utf-8']);
    }

}
