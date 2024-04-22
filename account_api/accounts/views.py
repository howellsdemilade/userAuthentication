from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.core.mail import send_mail
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate, login, logout
from rest_framework.authtoken.models import Token
from django.http import JsonResponse
from django.shortcuts import render
from django.urls import reverse
from .models import Activation, CustomUser
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.utils.encoding import force_str
from django.urls import reverse
from django.contrib.auth.hashers import make_password, check_password
from rest_framework.authtoken.models import Token
from django.utils.crypto import get_random_string
from .token import account_activation_token
from rest_framework_simplejwt.tokens import RefreshToken






@api_view(['POST'])
@permission_classes([AllowAny])
def SignupView(request):
    if request.method == "POST":
        # Extract data from request
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        hashed_password = make_password(password)
        
        if not username:
            return JsonResponse({'error': 'Username is required'})
        if not password:
            return JsonResponse({'error': 'Password is required'})
        if not email:
            return JsonResponse({'error': 'Email is required'})
        if not confirm_password:
            return JsonResponse({'error': 'Confirm_Password is required'})
        
        # Validate email format
        if not email or '@' not in email:
            return JsonResponse({"message": "Invalid email format"})

        # Check password match
        if password != confirm_password:
            return JsonResponse({"message": "Passwords do not match"})

        # Check if email already exists
        if CustomUser.objects.filter(email=email).exists():
            return JsonResponse({"message": "Email already exists"})

        # Create user
        user = CustomUser.objects.create(username=username, email=email, password=hashed_password)
        user.is_active = False
        user.save()


        # Generate activation link
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)        
        print("Token is ", token)
        activation_link = request.build_absolute_uri(reverse('activate', kwargs={'uidb64': uid, 'token': token}))

        # This is saving the activation
        activation = Activation.objects.create(user=user, token=token)


        # Render email template
        email_subject = "Activate Your Account"
        email_message = render_to_string('activate.html', {'user': user, 'activation_link': activation_link})

        # Send activation email
        try:
            send_mail(subject=email_subject, message="", html_message=email_message, from_email="howellsdemilade2007@gmail.com", recipient_list=[email])
        except Exception as e:
            # Handle email sending error
            print("Error is ==>", e)
            return JsonResponse({"message": "Account created successfully!! But Error sending activation email. Please try again!!."})

        # Provide feedback to the user about the activation email
        return JsonResponse({"message": "Account created successfully. Please check your email for the activation link."})

    else:
        return JsonResponse({"message": "Method not allowed"})





@api_view(['GET'])
@permission_classes([AllowAny])
def ActivationView(request, uidb64, token):
    if request.method == "GET":
        try: 
            uid = force_str(urlsafe_base64_decode(uidb64))
            print("Uid is ", uid)
            user = CustomUser.objects.get(pk=uid)
        # except Exception as ex:
        #     print("Exception is ===>", ex)
        #     return JsonResponse({'message': 'Invalid activation link. User not found.'})
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            return JsonResponse({'message': 'Invalid activation link. User not found.'})

        # Check if token is valid
        if not default_token_generator.check_token(user, token):
            return JsonResponse({'message': 'Invalid activation link or expired token.'})

        # Activate user
        user.status = "active"  
        user.save()

        # Delete activation record
        try:
            activation = Activation.objects.get(user=user, token=token)
            print("Activation is ", activation)
            activation.delete()
        except Activation.DoesNotExist:
            return JsonResponse({'message': 'Activation not found .'})

        return JsonResponse({'message': 'Your account has been activated successfully. You can now login.'})




@api_view(['POST'])
@permission_classes([AllowAny])
def LogoutView(request):
    if request.method == 'POST':
        # Logout the user
        logout(request)
        return Response({'message': 'Logout successful. Please ensure you discard any stored tokens.'})  
    return JsonResponse({'error': 'Method not allowed'})


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def RequestResetEmailView(request):
    if request.method == 'GET':
        return render(request, 'request_reset_email.html')
    elif request.method == 'POST':
        email = request.data.get('email')
        user = CustomUser.objects.filter(email=email).first()

        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = account_activation_token.make_token(user)
            reset_link = request.build_absolute_uri(reverse('set_new_password', kwargs={'uidb64': uid, 'token': token}))

            email_subject = '[Reset Your Password]'
            email_message = render_to_string('reset_user_password.html', {
                'domain': '127.0.0.1:8000',  # Change this to your actual domain
                'uid': uid,
                'token': token,
                'reset_link': reset_link,
            })

            try:
                send_mail(subject=email_subject, message="", html_message=email_message, from_email="howellsdemilade2007@gmail.com", recipient_list=[email])
                return Response({"message": "We have sent you an email with instructions on how to reset your password."})
            except Exception as e:
                return Response({"message": "Error sending password reset email. Please try again."})

        return Response({"message": "Doesn't Exist!!."})



@api_view(['POST'])
@permission_classes([AllowAny])
def SetNewPasswordView(request, uidb64, token):
    context = {
        'uidb64': uidb64,
        'token': token
    }
    if request.method == 'POST':
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')

        if password != confirm_password:
            return Response({"message": "Passwords do not match."})

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=user_id)

            if not account_activation_token.check_token(user, token):
                return Response({"message": "Password reset link is invalid or has expired."})

            user.set_password(password)
            user.save()
            return Response({"message": "Password reset successful. You can now login with your new password."})

        except Exception as e:
            return Response({"message": "Something went wrong. Please try again."})

    return render(request, 'set_new_password.html', context)




@api_view(['POST'])
@permission_classes([AllowAny])
def LoginView(request):
    if request.method == 'POST':
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username:
            return JsonResponse({'error': 'Username is required'})
        
        if not password:
            return JsonResponse({'error': 'Password is required'})
        # user = CustomUser.objects.filter(username=username, password=password).first()
        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'Invalid credentials'})

        # Check password
        if not check_password(password, user.password):  # Compare hashed passwords
            return JsonResponse({'error': 'Invalid credentials'})
        
        if user is None:
            return JsonResponse({'error': 'Authentication failed'}) 

        if user.status != 'active':
            return JsonResponse({'error': 'User is not active'})
        # Login user
        login(request, user)

         # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return JsonResponse({
            'username': user.username,
            'email': user.email,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'message': 'Login Successful!'
        })
    return JsonResponse({'error': 'Method not allowed'})
