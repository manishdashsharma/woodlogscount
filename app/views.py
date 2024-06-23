from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from config.dbconfig import *
from .serializers import *
from .utils.helper import *
from bson import ObjectId
import bcrypt 
from datetime import datetime
from .services.auth_decorator import *
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings

jwt_utils = JWTUtils()

@method_decorator(csrf_exempt, name='dispatch')
class api_services_info(APIView):
    def get(self, request):
        type = request.GET.get('type')
        if type =='auth-service':
            return self.auth_services(request)
        elif type == 'api-service':
            return self.api_services(request)
        else:
            return self.handle_error(request)
    
    def api_services(self, request):
        return Response({
            "success": True,
            "message": "Welcome to our API service and it is healthy!"
        }, status=status.HTTP_200_OK)

    def auth_services(self, request):
        return Response({
            "success": True,
            "message": "Welcome to our auth service and it is healthy!"
        }, status=status.HTTP_200_OK)
        
    def handle_error(self, request): 
        return Response({
            "success": False,
            "message": "Invalid request type"
        }, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class authentication_services(APIView):

    def post(self, request):
        type = request.GET.get('type')
        if type == 'signup':
            return self.signup_user(request)
        elif type == 'login':
            return self.login_user(request)
        elif type == 'logout':
            return self.logout_user(request)
        elif type == 'forgot_password':
            return self.forgot_password(request)
        elif type == 'get_access_token':
            return self.get_access_token(request)
        else:
            return self.handle_error(request)     
    def get(self, request):
        type = request.GET.get('type')
        if type =='user_profile':
            return self.user_profile(request)
        elif type =='get_check_post_officer_under_admin':
            return self.get_check_post_officer_under_admin(request)
        elif type =='get_admins':
            return self.get_admins(request)
        
        else:
            return self.handle_error(request)

    def signup_user(self, request):
        email = request.data.get('email')
        name = request.data.get('name')
        username = request.data.get('username')
        password = request.data.get('password')
        role = request.data.get('role')
        admin_id = request.data.get('admin_id')

        serializer = SignupSerializer(data={
            'email': email,
            'name': name,
            'username': username,
            'password': password,
            'role': role,
            'admin_id': admin_id
        })
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Invalid data",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        
        if role == 'check_post_officer':
            admins = database.child("user").get().val()
            if admins is None:
                return Response({
                    "success": False,
                    "message": "No admin users found"
                }, status=status.HTTP_404_NOT_FOUND)
            admin_exists = False
            for _, user_data in admins.items():
                if user_data['role'] == 'admin' and user_data.get('admin_id') == admin_id:
                    admin_exists = True
                    break
            if not admin_exists:
                return Response({
                    "success": False,
                    "message": "Specified admin does not exist"
                }, status=status.HTTP_400_BAD_REQUEST)

        
        existing_user = database.child("user").child(username).get()
        if existing_user.val() is not None:
            return Response({
                "success": False,
                "message": "Username already exists"
            }, status=status.HTTP_400_BAD_REQUEST)

       
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user_data = {
            "_id": str(ObjectId()),
            "name": name,
            "username": username,
            "password": hashed_password,
            "email": email,
            "role": role,
            "admin_id": admin_id,
            "refresh_token": "",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }

        response = database.child("user").child(username).set(user_data)
        if response is None:
            return Response({
                "success": False,
                "message": "Error saving user to the database"
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "success": True,
            "message": "User created successfully",
            "response": {
                "email": email,
                "name": name,
                "username": username,
                "role": role,
                "admin_id": admin_id,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
        })

    def login_user(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        serializer = LoginSerializer(data={
            'username': username,
            'password':  password
        })

        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Posting wrong data to API",
                "error": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        user = database.child("user").child(username).get().val()
        if user is None:
            return Response({
                "success": False,
                "message": "User not found"
            }, status=status.HTTP_404_NOT_FOUND)

       
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return Response({
                "success": False,
                "message": "Incorrect password"
            }, status=status.HTTP_401_UNAUTHORIZED)

      
        get_jwt_token = jwt_utils.generate_jwt_tokens(user["_id"], user["username"], user["email"], user["role"])

        if 'error' in get_jwt_token:
            return Response({
                "success": False,
                "message": "Error generating JWT tokens",
                "error": get_jwt_token['error']
            }, status=status.HTTP_400_BAD_REQUEST)

        user["refresh_token"] = get_jwt_token['refresh_token']
        user["updated_at"] = datetime.utcnow().isoformat()
        response = database.child("user").child(username).update(user)
        if response is None:
            return Response({
                "success": False,
                "message": "Error updating user token in the database"
            }, status=status.HTTP_400_BAD_REQUEST)

        
        response = Response({
            "success": True,
            "message": "Login successful",
            "access_token": get_jwt_token["access_token"],
            "refresh_token" : get_jwt_token["refresh_token"],
            "response": {
                "email": user["email"],
                "name": user["name"],
                "username": user["username"],
                "role": user["role"],
                "admin_id": user["admin_id"],
                "updated_at": datetime.utcnow().isoformat()
            }
        }, status=status.HTTP_200_OK)

        access_token = get_jwt_token["access_token"]
        refresh_token = get_jwt_token["refresh_token"]
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            secure=True,  
            samesite='Lax'  
        )
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,
            secure=True,  
            samesite='Lax'  
        )

        return response

    @login_required
    def logout_user(self,request):
        response = Response({
            "success": True,
            "message": "Successfully logged out"
        }, status=status.HTTP_200_OK)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response

    @login_required
    def forgot_password(self,request):
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        serializer = ForgotPasswordSerializer(data={
            'old_password':  old_password,
            'new_password':  new_password
        })

        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Posting wrong data to API",
                "error": serializer.errors
            }, status= status.HTTP_400_BAD_REQUEST)
        
        user = database.child("user").child(request.user['username']).get().val()
        if user is None:
            return Response({
                "success": False,
                "message": "User not found"
            }, status=status.HTTP_404_NOT_FOUND)

       
        if not bcrypt.checkpw(old_password.encode('utf-8'), user['password'].encode('utf-8')):
            return Response({
                "success": False,
                "message": "Old password is incorrect password"
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user["password"] =  hashed_password
        response = database.child("user").child(request.user['username']).update(user)
        if response is None:
            return Response({
                "success": False,
                "message": "Error updating user password in the database"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            "success": True,
            "message": "Password updated successfully"
        }, status=status.HTTP_200_OK)

    def get_access_token(self, request):
        refresh_token = request.COOKIES.get('refresh_token') or request.headers.get('Authorization', '').replace('Bearer ', '') or request.data.get('refresh_token')
            
        if not refresh_token:
            return Response({
                "success": False,
                "message": "Refresh token not provided"
            }, status=status.HTTP_401_UNAUTHORIZED)

        decoded_payload = jwt_utils.decode_jwt_token(refresh_token)
        if not decoded_payload:
            return Response({
                "success": False,
                "message": "Invalid refresh token"
            }, status=status.HTTP_401_UNAUTHORIZED)

        user = database.child("user").child(decoded_payload['username']).get().val()
        if user is None:
            return Response({
                "success": False,
                "message": "User not found"
            }, status=status.HTTP_404_NOT_FOUND)

        user_refresh_token = jwt_utils.decode_jwt_token(user.get('refresh_token'))

        if user_refresh_token['_id'] != decoded_payload["_id"]:
            return Response({
                "success": False,
                "message": "Invalid refresh token"
            }, status=status.HTTP_401_UNAUTHORIZED)

        new_access_token = jwt_utils.generate_jwt_tokens(
            decoded_payload['_id'],
            decoded_payload['username'],
            decoded_payload['email'],
            decoded_payload['role']
        )['access_token']

        # Update refresh token in the database
        new_refresh_token = jwt_utils.generate_jwt_tokens(
            decoded_payload['_id'],
            decoded_payload['username'],
            decoded_payload['email'],
            decoded_payload['role']
        )['refresh_token']
        user['refresh_token'] = new_refresh_token
        database.child("user").child(decoded_payload['username']).update(user)

        return Response({
            "success": True,
            "message": "Access token generated successfully",
            "access_token": new_access_token,
            "refresh_token": new_refresh_token
        }, status=status.HTTP_200_OK)

    @login_required
    def user_profile(self, request):
        user = database.child("user").child(request.user['username']).get().val()
        if user is None:
            return Response({
                "success": False,
                "message": "User not found"
            }, status=status.HTTP_404_NOT_FOUND)

        return Response({
            "success": True,
            "message": "User profile retrieved successfully",
            "response": {
                "email": user["email"],
                "name": user["name"],
                "username": user["username"],
                "role": user["role"],
                "admin_id": user["admin_id"],
                "updated_at": datetime.utcnow().isoformat()
            }
        }, status=status.HTTP_200_OK)

    def get_check_post_officer_under_admin(self, request):
        admin_id = request.GET.get('admin_id')
        if admin_id is None:
            return Response({
                "success": False,
                "message": "Admin id not provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        admin_data = database.child("user").get().val()
        if admin_data is None:
            return Response({
                "success": False,
                "message": "No users found"
            }, status=status.HTTP_404_NOT_FOUND)

        check_post_officers = []
        for username, user_data in admin_data.items():
            if user_data['role'] == 'admin' and user_data.get('admin_id') == admin_id:
                for sub_username, sub_user_data in admin_data.items():
                    if sub_user_data['role'] == 'check_post_officer' and sub_user_data.get('admin_id') == admin_id:
                        check_post_officers.append({
                            "_id": sub_user_data['_id'],
                            "name": sub_user_data['name']
                        })
                break

        return Response({
            "success": True,
            "message": "Check post officers under admin retrieved successfully",
            "check_post_officers": check_post_officers
        })
    
    def get_admins(self, request):
        admins = []
        admin_data = database.child("user").get().val()
        if admin_data is None:
            return Response({
                "success": False,
                "message": "No users found"
            }, status=status.HTTP_404_NOT_FOUND)

        for username, user_data in admin_data.items():
            if user_data['role'] == 'admin':
                admins.append({
                    "_id": user_data['_id'],
                    "name": user_data['name']
                })

        return Response({
            "success": True,
            "message": "Admins retrieved successfully",
            "response": admins
        })

    def handle_error(self, request): 
        return Response({
            "success": False,
            "message": "Invalid request type"
        }, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class check_post_services(APIView):
    def post(self, request):
        type = request.GET.get('type')
        if type == 'register_check_post':
            return self.register_check_post(request)
        else:
            return self.handle_error(request) 
    def get(self, request):
        type = request.GET.get('type')
        if type == 'get_check_post_list':
            return self.get_check_post_list(request)
        elif type == 'get_check_post_list_by_check_post_officer':
            return self.get_check_post_list_by_check_post_officer(request)
        else:
            return self.handle_error(request)
    
    @login_required
    @admin_required
    def register_check_post(self, request):
        name = request.data.get('name')
        description = request.data.get('description')
        location = request.data.get('location')
        latitude = request.data.get('latitude')
        longitude = request.data.get('longitude')
        list_of_check_post_officer = request.data.get('list_of_check_post_officer')
        check_post_admin_id = request.GET.get('check_post_admin_id')
        
        if check_post_admin_id is None:
            return Response({
                "success": False,
                "message": "Check post admin id not provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = CheckPostSerializer(data={
            'name': name,
            'description': description,
            'location': location,
            'latitude': latitude,
            'longitude': longitude,
            'list_of_check_post_officer': list_of_check_post_officer
        })

        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Posting wrong data to API",
                "error": serializer.errors
            }, status= status.HTTP_400_BAD_REQUEST)
        
        existing_check_post = database.child("checkpost").child(name).get()
        if existing_check_post.val() is not None:
            return Response({
                "success": False,
                "message": "Check post name already exists"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        data = {
            "_id": str(ObjectId()),
            "name": name,
            "description": description,
            "location": location,
            "latitude": latitude,
            "longitude": longitude,
            "list_of_check_post_officer": list_of_check_post_officer,
            "check_post_admin_id": check_post_admin_id,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }

        response = database.child("checkpost").child(name).set(data)
        if response is None:
            return Response({
                "success": False,
                "message": "Error registering check post in the database"
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "success": True,
            "message": "Check post registered successfully",
            "response": {
                "name": name,
                "description": description,
                "location": location,
                "latitude": latitude,
                "longitude": longitude,
                "list_of_check_post_officer": list_of_check_post_officer,
                "check_post_admin_id": check_post_admin_id
            }
        })

    @login_required
    @admin_required
    def get_check_post_list(self, request):
        check_post_admin_id = request.GET.get('check_post_admin_id')
        if check_post_admin_id is None:
            return Response({
                "success": False,
                "message": "Check post admin id not provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        check_post_data = database.child("checkpost").get().val()
        if check_post_data is None:
            return Response({
                "success": False,
                "message": "No check posts found"
            }, status=status.HTTP_404_NOT_FOUND)

        check_post_list = []
        for check_post_name, check_post_data in check_post_data.items():
            if check_post_data['check_post_admin_id'] == check_post_admin_id:
                check_post_list.append({
                    "_id": check_post_data['_id'],
                    "name": check_post_data['name'],
                    "description": check_post_data['description'],
                    "location": check_post_data['location'],
                    "latitude": check_post_data['latitude'],
                    "longitude": check_post_data['longitude'],
                    "list_of_check_post_officer": check_post_data['list_of_check_post_officer'],
                    "check_post_admin_id": check_post_data['check_post_admin_id']
                })
        
        return Response({
            "success": True,
            "message": "Check post list retrieved successfully",
            "response": check_post_list
        },status=status.HTTP_200_OK)
    
    @login_required
    def get_check_post_list_by_check_post_officer(self,request):
        check_post_officer_id = request.GET.get('check_post_officer_id')
        if check_post_officer_id is None:
            return Response({
                "success": False,
                "message": "Check post officer id not provided"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        check_post_data_list = (database.child("checkpost").get()).val()
        if isinstance(check_post_data_list, dict):
                check_post_data_list = list(check_post_data_list.values())

        officer_check_posts = []
        for check_post in check_post_data_list:
            if check_post_officer_id in check_post.get("list_of_check_post_officer", []):
                officer_check_posts.append(check_post)

        return Response({
            "success": True,
            "message": "Check post list retrieved successfully",
            "response": officer_check_posts
        })
    
    def handle_error(self, request): 
        return Response({
            "success": False,
            "message": "Invalid request type"
        }, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class woodlogs_count_check(APIView):
    def post(self, request):
        type = request.GET.get('type')
        if type == 'upload_woodlog_image':
            return self.upload_woodlog_image(request)
        else:
            return self.handle_error(request)
        
    @login_required
    def upload_woodlog_image(self, request):
        check_post_id = request.data.get('check_post_id')
        check_post_officer_id = request.data.get('check_post_officer_id')
        image = request.FILES.get('image')
        name = request.data.get('name')

        if not check_post_id or not check_post_officer_id or not image:
            return Response({
                "success": False,
                "message": "check_post_id, check_post_officer_id, and image are required."
            }, status=status.HTTP_400_BAD_REQUEST)

       
        file_name = f"{check_post_id}_{check_post_officer_id}.jpg"
        file_path = os.path.join(settings.MEDIA_ROOT, file_name)

        try:
            path = default_storage.save(file_path, ContentFile(image.read()))
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Error saving image: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

        image_url = request.build_absolute_uri(settings.MEDIA_URL + file_name)

        try:
            count = count_logs(file_path)
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Error counting logs: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        woodlog_data = {
            "_id": str(ObjectId()),
            "check_post_id": check_post_id,
            "check_post_officer_id": check_post_officer_id,
            "image_url": image_url,
            "name": name,
            "count": count,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        try:
            database.child("woodlogs").child(name).set(woodlog_data)
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Error saving image path to database: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "success": True,
            "message": "Image uploaded successfully",
            "response": woodlog_data
        }, status=status.HTTP_200_OK)

    def handle_error(self, request): 
        return Response({
            "success": False,
            "message": "Invalid request type"
        }, status=status.HTTP_400_BAD_REQUEST)