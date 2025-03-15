from django.shortcuts import render
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.authtoken.models import Token
from .serializers import UserSerializer
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth import logout

def home(request):
    return JsonResponse({"message": "Welcome to Wealth-Wave Backend!"})

@api_view(['POST'])
def signup(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = User.objects.create_user(
            username=request.data['username'],
            email=request.data.get('email', ''),  # Email is optional
            password=request.data['password']
        )
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'user': serializer.data}, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def login(request):
    identifier = request.data.get('identifier', '').strip()  # Ensure it's not None
    password = request.data.get('password', '').strip()

    if not identifier or not password:
        return Response({'error': 'Identifier and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    user = None
    if '@' in identifier:  # If it's an email, find the user by email
        try:
            user = User.objects.get(email=identifier)
            user = authenticate(username=user.username, password=password)
        except User.DoesNotExist:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)
    else:  # If it's a username, authenticate normally
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
        # Delete the token to log out the user
        request.auth.delete()
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
    except AttributeError:
        return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)