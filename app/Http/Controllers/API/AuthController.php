<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{
    public function register(Request $request){
        $validator = Validator::make($request ->all(),[
            'name'=>'required|max:191',
            'email'=>'required|email|max:191|unique:users,email',
            'password'=>'required|min:8',
        ]);
        if ($validator->fails()){
            return response()->json([
                'validation_errors'=>$validator->messages(),
            ]);
        }else{
            $user = User::create([
                'name'=>$request->name,
                'email'=>$request->email,
                'password'=>Hash::make($request->password),
            ]);
            
            $token = $user->createToken($user->email.'_Token')->plainTextToken;

            return response()->json([
                'status'=>200,
                'username'=>$user->name,
                'token'=>$token,
                'message'=>'Registro exitoso',
            ]);
        }
    }

    public function login(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required|max: 191',
            'password' => 'required',
        ]);
        if($validator->fails()){
            return response()->json([
                'validation_errors'=>$validator->messages(),
            ]);
        }else{
            $user = User::where('email', $request->email)->first();
            if(!$user || !Hash::check($request->password, $user->password)){
                return response()->json([
                    'status'=>401,
                    'message'=>'Los datos ingresados no son correctos',
                ]);
            }else{
                $token = $user->createToken($user->email.'_Token')->plainTextToken;

                return response()->json([
                    'status'=>200,
                    'username'=>$user->name,
                    'token'=>$token,
                    'message'=>'Has iniciado sesión con exitoso',
                ]);

            }
        }
    }

    public function logout(){
        auth()->user()->tokens()->delete();
        return response()->json([
            'status'=>200,
            'message'=>'Has cerrado sesión con exito',
        ]);
    }
}
