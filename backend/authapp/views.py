from django.shortcuts import render
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.authtoken.models import Token
from .serializers import UserSerializer
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth import logout

def home(request):
    return JsonResponse({"message": "Welcome to Wealth-Wave Backend!"})

@api_view(['POST'])
def signup(request):
    first_name = request.data.get('first_name', '').strip()
    last_name = request.data.get('last_name', '').strip()
    email = request.data.get('email', '').strip()
    password = request.data.get('password', '').strip()
    username = request.data.get('username', '').strip()

    if not first_name or not last_name or not email or not password:
        return Response({'error': 'First name, last name, email, and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({'error': 'Email is already registered'}, status=status.HTTP_400_BAD_REQUEST)

    # Generate a username if not provided
    if not username:
        base_username = f"{first_name.lower()}{last_name.lower()}"
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username is already taken'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=password
    )

    token, _ = Token.objects.get_or_create(user=user)

    return Response({'token': token.key, 'user': {
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email
    }}, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def login(request):
    identifier = request.data.get('identifier', '').strip()  # Can be username or email
    password = request.data.get('password', '').strip()

    if not identifier or not password:
        return Response({'error': 'Identifier and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    user = None
    if '@' in identifier:  # If email is used
        try:
            user = User.objects.get(email__iexact=identifier)  # Case-insensitive match
            user = authenticate(username=user.username, password=password)
        except User.DoesNotExist:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)
    else:  # If username is used
        user = authenticate(username=identifier, password=password)

    if user:
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)

    return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def logout_view(request):
    try:
        # Ensure token exists before deletion
        if request.auth:
            request.auth.delete()
            return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
