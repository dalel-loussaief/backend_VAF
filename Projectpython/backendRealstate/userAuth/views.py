from decimal import Decimal

from rest_framework.decorators import api_view, parser_classes
from rest_framework.generics import RetrieveAPIView

from django.shortcuts import get_object_or_404


from django.core.mail import send_mail
from rest_framework.decorators import api_view

from django.contrib.auth.hashers import make_password

from django.views.decorators.csrf import csrf_exempt

from .serializer import RoleSerializer, TemoinageSerializer, BlogSerializer, ContactSerializer, RegisterSerializer, \
    RdvSerializer, PropertySerializer, ImageSerializer, ServiceSerializer, CategorySerializer, PropertyinfoSerializer, \
    ReviewSerializer
from .models import User, Temoinage, Blog, Contact, RDV, Image, Property, Service, Category, PropertyInfo

from .models import Property

import jwt, datetime
from django.conf import settings

from .serializer import PropertyinfoSerializer
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import parser_classes
from rest_framework import generics

from .serializer import UserSerializer
# Create your views here.


from .models import User, Role

"""User"""
@api_view(['POST'])
def create_user(request):
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
def updateUser(request, pk):
    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def deleteUser(request, pk):
    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        user.delete()
        return Response({"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
def searchUserById(request, pk):
    try:
        user = User.objects.get(pk=pk)
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
def list_users(request):
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

"""Role"""
@api_view(['POST'])
def create_role(request):
    if request.method == 'POST':
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@api_view(['PUT'])
def update_role(request, pk):
    try:
        role = Role.objects.get(pk=pk)
    except Role.DoesNotExist:
        return Response({"message": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = RoleSerializer(role, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def delete_role(request, pk):
    try:
        role = Role.objects.get(pk=pk)
    except Role.DoesNotExist:
        return Response({"message": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        role.delete()
        return Response({"message": "Role deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

"""Temoinage"""
@api_view(['POST'])
def create_temoinage(request):
        if request.method == 'POST':
            serializer = TemoinageSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
def update_temoinage(request, pk):
    try:
        temoinage = Temoinage.objects.get(pk=pk)
    except Temoinage.DoesNotExist:
        return Response({"message": "Temoinage not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = TemoinageSerializer(temoinage, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@api_view(['DELETE'])
def delete_temoinage(request, pk):
    try:
        temoinage = Temoinage.objects.get(pk=pk)
    except Temoinage.DoesNotExist:
        return Response({"message": "Temoinage not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        temoinage.delete()
        return Response({"message": "Temoinage deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
def list_temoinages(request):
    temoinages = Temoinage.objects.all()
    serializer = TemoinageSerializer(temoinages, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def searchTemoinageById(request, pk):
    try:
        temoinage = Temoinage.objects.get(pk=pk)
        serializer = TemoinageSerializer(temoinage)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Temoinage.DoesNotExist:
        return Response({"message": "Temoinage not found"}, status=status.HTTP_404_NOT_FOUND)


"""Blog"""
@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def create_blog(request):
        if request.method == 'POST':
            serializer = BlogSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
def update_blog(request, pk):
    try:
        blog = Blog.objects.get(pk=pk)
    except Blog.DoesNotExist:
        return Response({"message": "Blog not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = BlogSerializer(blog, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def delete_blog(request, pk):
    try:
        blog = Blog.objects.get(pk=pk)
    except Blog.DoesNotExist:
        return Response({"message": "Blog not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        blog.delete()
        return Response({"message": "Blog deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
def list_blogs(request):
    blogs = Blog.objects.all()
    serializer = BlogSerializer(blogs, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def searchBlogById(request, pk):
    try:
        blog = Blog.objects.get(pk=pk)
        serializer = BlogSerializer(blog)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Blog.DoesNotExist:
        return Response({"message": "Blog not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def ViewBlog(request, pk):
    try:
        blog = Blog.objects.get(id=pk)
    except Blog.DoesNotExist:
        return Response({"message": "Blog does not exist"}, status=status.HTTP_404_NOT_FOUND)

    serializer = BlogSerializer(blog)
    return Response(serializer.data)


"""Contact"""
@api_view(['POST'])
def add_contact(request):
    if request.method == 'POST':
        serializer = ContactSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
def update_contact(request, pk):
    try:
        contact = Contact.objects.get(pk=pk)
    except Contact.DoesNotExist:
        return Response({"message": "Contact not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = ContactSerializer(contact, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def delete_contact(request, pk):
    try:
        contact = Contact.objects.get(pk=pk)
    except Contact.DoesNotExist:
        return Response({"message": "Contact not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        contact.delete()
        return Response({"message": "Contact deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
def list_contacts(request):
    contacts = Contact.objects.all()
    serializer = ContactSerializer(contacts, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def searchContactById(request, pk):
    try:
        contact = Contact.objects.get(pk=pk)
        serializer = ContactSerializer(contact)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Contact.DoesNotExist:
        return Response({"message": "Contact not found"}, status=status.HTTP_404_NOT_FOUND)





"""Register / Login"""
class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        user.set_password(request.data.get('password'))  # Set password before saving
        user.save()
        return Response(serializer.data)



class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Vérification de l'existence de l'utilisateur
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found!')

        # Vérification du mot de passe
        if not check_password(password, user.password):
            raise AuthenticationFailed('Incorrect password!')

        # Génération du token JWT
        token = generate_jwt_token(user)
        return Response({'token': token, 'role': user.role_id.name})

def generate_jwt_token(user):
    payload = {
        'user_id': user.id,
        'exp': timezone.now() + timezone.timedelta(minutes=60),
        'iat': timezone.now()
    }
    # Vous pouvez ajouter d'autres informations dans le payload si nécessaire
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


class UserView(APIView):
    permission_classes = []

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token!')

        user_id = payload.get('user_id')
        user = User.objects.filter(id=user_id).first()

        if not user:
            raise AuthenticationFailed('User not found!')

        serializer = RegisterSerializer(user)
        return Response(serializer.data)

class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response


class UserListAPIView(generics.ListAPIView):
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(role_id=3)


class UserListByRoleId2APIView(generics.ListAPIView):
    queryset = User.objects.filter(role_id=2)
    serializer_class = UserSerializer

class UserListByRoleId3APIView(generics.ListAPIView):
    queryset = User.objects.filter(role_id=3)
    serializer_class = UserSerializer




@csrf_exempt
def change_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'message': 'Utilisateur non trouvé'}, status=404)

        if not check_password(old_password, user.password):
            return JsonResponse({'message': 'Mot de passe incorrect'}, status=400)

        user.password = make_password(new_password)
        user.save()
        # Dans votre vue Django
        print(request.POST)

        return JsonResponse({'message': 'Mot de passe changé avec succès'}, status=200)
    else:
        return JsonResponse({'message': 'Méthode non autorisée'}, status=405)


from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import User

#@api_view(['GET'])
#def get_role_by_email(request, email):
    #try:
        #user = User.objects.get(email=email)
        #role_name = user.role_id.name if user.role_id else "No role assigned"
        #return Response({'role': role_name})
    #except User.DoesNotExist:
        #return Response({'error': 'User not found'}, status=404)




@api_view(['GET'])
def get_user_role(request, email):
    user = get_object_or_404(User, email=email)
    role = user.role_id.name if user.role_id else None
    data = {'email': user.email, 'role': role}
    return Response(data)



@api_view(['POST'])
def create_rdv(request):
        if request.method == 'POST':
            serializer = RdvSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def delete_rdv(request, pk):
    try:
        rdv = RDV.objects.get(pk=pk)
    except RDV.DoesNotExist:
        return Response({"message": "RDV not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        rdv.delete()
        return Response({"message": "RDV deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
def list_rdvs(request):
    rdvs = RDV.objects.all()
    serializer = RdvSerializer(rdvs, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)





@api_view(['POST'])
def envoyer_email(request):
    if request.method == 'POST':
        data = request.data
        email_destinataire = data.get('email_destinataire')
        contenu_email = data.get('contenu_email')

        try:
            send_mail(
                'Objet de l\'email',
                contenu_email,
                'votre@email.com',  # L'adresse email de l'expéditeur
                [email_destinataire],
                fail_silently=False,
            )
            return Response({'message': 'Email envoyé avec succès !'})
        except Exception as e:
            return Response({'message': 'Erreur lors de l\'envoi de l\'e-mail : ' + str(e)}, status=500)


@api_view(['GET'])
def ShowAll(request):
    property = Property.objects.all()
    serializer = PropertyinfoSerializer(property, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def  ViewProperty(request, id):
    property = Property.objects.get(id=id)
    serializer = PropertyinfoSerializer(property, many=False)
    return Response(serializer.data)


from django.contrib.auth.decorators import login_required
@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def CreateProperty(request):
    if request.method == 'POST':

        serializer = PropertySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def updateProperty(request, pk):
    try:
        property_instance = Property.objects.get(id=pk)
    except Property.DoesNotExist:
        return Response({"error": "Property not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = PropertyInfoSerializer(instance=property_instance, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def deleteProperty(request, pk):
    try:
        property_instance = Property.objects.get(id=pk)
    except Property.DoesNotExist:
        return Response({"error": "Property not found"}, status=status.HTTP_404_NOT_FOUND)

    property_instance.delete()
    return Response('Item deleted successfully!', status=status.HTTP_200_OK)

@api_view(['GET'])
def searchPropertyById(request, pk):
    try:
        property_instance = Property.objects.get(id=pk)
        serializer = PropertySerializer(property_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Property.DoesNotExist:
        return Response({"error": "Property not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def Show(request):
    category = Category.objects.all()
    serializer = CategorySerializer(category, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def ViewCategory(request, pk):
    category = Category.objects.get(category_id=pk)
    serializer = CategorySerializer(category, many=False)
    return Response(serializer.data)


@api_view(['POST'])
def CreateCategory(request):
    if request.method == 'POST':
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def updateCategory(request, pk):
    try:
        category_instance = Category.objects.get(category_id=pk)
    except Category.DoesNotExist:
        return Response({"error": "category not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = CategorySerializer(instance=category_instance, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['DELETE'])
def deleteCategory(request, pk):
    try:
        category_instance = Category.objects.get(category_id=pk)
    except Category.DoesNotExist:
        return Response({"error": "category not found"}, status=status.HTTP_404_NOT_FOUND)

    category_instance.delete()
    return Response('Category deleted successfully!', status=status.HTTP_200_OK)


@api_view(['GET'])
def searchCategoryById(request, pk):
    try:
        category_instance = Category.objects.get(category_id=pk)
        serializer = CategorySerializer(category_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Category.DoesNotExist:
        return Response({"error": "category not found"}, status=status.HTTP_404_NOT_FOUND)


from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Category, Service, PropertyInfo
from .serializer import PropertyInfoSerializer

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import PropertyInfo, Category, Service
from .serializer import PropertyInfoSerializer
""""
@api_view(['GET'])
def properties_by_category_and_service(request, category_id, id_service):
    try:
        category_instance = Category.objects.get(category_id=category_id)
    except Category.DoesNotExist:
        return Response({"error": "Category not found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        service_instance = Service.objects.get(id_service=id_service)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)

    properties = PropertyInfo.objects.filter(category=category_instance, service=service_instance)
    serializer = PropertyInfoSerializer(properties, many=True)
    properties_data = serializer.data

    # Ajouter l'ID de la propriété à chaque objet de propriété
    for i, property_data in enumerate(properties_data):
        property_data['id'] = properties[i].id

    return Response(properties_data, status=status.HTTP_200_OK)

"""
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Category, Service, PropertyInfo, Localisation
from .serializer import PropertyInfoSerializer

@api_view(['GET'])
def properties_by_category_and_services_Localisation(request, category_id, id_service, location_id):
    try:
        category_instance = Category.objects.get(category_id=category_id)
    except Category.DoesNotExist:
        return Response({"error": "Category not found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        service_instance = Service.objects.get(id_service=id_service)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        location_instance = Localisation.objects.get(id=location_id)
    except Localisation.DoesNotExist:
        return Response({"error": "Location not found"}, status=status.HTTP_404_NOT_FOUND)

    properties = PropertyInfo.objects.filter(category=category_instance, service=service_instance, localisation=location_instance)
    serializer = PropertyInfoSerializer(properties, many=True)
    properties_data = serializer.data

    return Response(properties_data, status=status.HTTP_200_OK)


@api_view(['GET'])
def ShowAll(request):
    services = Service.objects.all()
    serializer = ServiceSerializer(services, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def ViewService(request, pk):
    try:
        service = Service.objects.get(id_service=pk)
    except Service.DoesNotExist:
        return Response({"message": "Service does not exist"}, status=status.HTTP_404_NOT_FOUND)

    serializer = ServiceSerializer(service)
    return Response(serializer.data)


@api_view(['POST'])
def CreateService(request):
    if request.method == 'POST':
        serializer = ServiceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def updateService(request, pk):
    try:
        service_instance = Service.objects.get(id_service=pk)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = ServiceSerializer(instance=service_instance, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def deleteService(request, pk):
    try:
        service_instance = Service.objects.get(id_service=pk)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)

    service_instance.delete()
    return Response('Item deleted successfully!', status=status.HTTP_200_OK)


@api_view(['GET'])
def searchServiceById(request, pk):
    try:
        service_instance = Service.objects.get(id_service=pk)
        serializer = ServiceSerializer(service_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)









@api_view(['POST'])
@parser_classes([MultiPartParser])
def createImage(request):
    if request.method == 'POST':
        serializer = ImageSerializer(data=request.data)
        if serializer.is_valid():
            property_id = request.data.get('property_id')
            try:
                property_instance = Property.objects.get(id=property_id)
            except Property.DoesNotExist:
                return Response({"error": "Property not found"}, status=status.HTTP_404_NOT_FOUND)

            image_file = request.data.get('image')
            image_content_type = image_file.content_type

            # Vérifiez le type de contenu de l'image avant de la sauvegarder
            if image_content_type not in ['image/jpeg', 'image/png', 'image/gif']:
                return Response({"error": "Unsupported image format"}, status=status.HTTP_400_BAD_REQUEST)

            # Associer l'image à la propriété et la sauvegarder
            serializer.save(property=property_instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@parser_classes([MultiPartParser])
def updateImage(request, pk):
    try:
        image_instance = Image.objects.get(idImage=pk)  # Utilisez le champ correct ici
    except Image.DoesNotExist:
        return Response({"error": "Image not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = ImageSerializer(instance=image_instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def deleteImage(request, pk):
    try:
        image_instance = Image.objects.get(idImage=pk)  # Utilisez le champ d'identification correct ici
    except Image.DoesNotExist:
        return Response({"error": "Image not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        image_instance.delete()
        return Response({"message": "Image deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
def list_properties(request):
    properties = PropertyInfo.objects.all()
    serializer = PropertyinfoSerializer(properties, many=True)
    return Response(serializer.data)


""""
@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def create_propertyinfo(request):
    if request.method == 'POST':
        serializer = PropertyinfoSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
"""
from rest_framework.decorators import api_view, parser_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def create_propertyinfo(request):
    if request.method == 'POST':
        serializer = PropertyinfoSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            error_msg = "Invalid data. Please check the input."
            return Response({"error": error_msg, "details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    else:
        error_msg = "Invalid request method. Only POST method is allowed."
        return Response({"error": error_msg}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['GET'])
def get_properties_by_email(request, email):
    try:
        properties = PropertyInfo.objects.filter(owner_email=email)
        serializer = PropertyinfoSerializer(properties, many=True)
        return Response(serializer.data)
    except PropertyInfo.DoesNotExist:
        return Response({'message': 'No properties found for this email'}, status=404)
    except Exception as e:
        return Response({'error': str(e)},status=500)



class PropertyInfoDeleteAPIView(generics.DestroyAPIView):
    queryset = PropertyInfo.objects.all()
    serializer_class = PropertyinfoSerializer

    def delete(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(status=status.HTTP_204_NO_CONTENT)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)





from rest_framework.decorators import api_view

from .serializer import PropertyinfoSerializer

@api_view(['GET'])

def get_property_detail(request, id):
    try:
        property_info = PropertyInfo.objects.filter(id=id).first()
        if property_info:
            serializer = PropertyinfoSerializer(property_info)
            property_data = serializer.data
            property_data['id'] = property_info.id  # Ajoutez l'ID à l'objet de propriété
            return Response(property_data, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Property does not exist'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PropertyDetailView(RetrieveAPIView):
    queryset = Property.objects.all()
    serializer_class = PropertyinfoSerializer
    lookup_field = 'id'  # Utilisez 'id' comme champ de recherche

from rest_framework import status

@api_view(['PUT'])
def update_property(request, id):
    try:
        property_info = PropertyInfo.objects.get(id=id)
    except PropertyInfo.DoesNotExist:
        return Response({'message': 'Property does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = PropertyInfoSerializer(property_info, data=request.data)
        if serializer.is_valid():
            serializer.save()
            updated_property_info = serializer.data
            updated_property_info['id'] = id
            return Response(updated_property_info)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['GET'])
def properties_by_category(request, category_id):
    try:
        category_instance = Category.objects.get(category_id=category_id)
    except Category.DoesNotExist:
        return Response({"error": "Category not found"}, status=status.HTTP_404_NOT_FOUND)


    properties = PropertyInfo.objects.filter(category=category_instance)
    serializer = PropertyInfoSerializer(properties, many=True)
    properties_data = serializer.data

    # Ajouter l'ID de la propriété à chaque objet de propriété
    for i, property_data in enumerate(properties_data):
        property_data['id'] = properties[i].id

    return Response(properties_data, status=status.HTTP_200_OK)


from rest_framework.decorators import api_view

from django.core.exceptions import ValidationError


@api_view(['GET'])
def get_properties_by_price_range(request):
    if request.method == 'GET':
        min_price = request.GET.get('min_price')
        max_price = request.GET.get('max_price')

        # Validation des paramètres
        if min_price is None or max_price is None:
            return Response({'error': 'Les paramètres min_price et max_price sont requis.'}, status=400)

        try:
            # Convertir les prix en entiers
            min_price = int(min_price.replace(',', ''))
            max_price = int(max_price.replace(',', ''))

            # Filtrer les propriétés par plage de prix
            properties = PropertyInfo.objects.filter(property_prix__gte=min_price, property_prix__lte=max_price)
            serializer = PropertyInfoSerializer(properties, many=True)
            properties_data = serializer.data

            for i, property_data in enumerate(properties_data):
                property_data['id'] = properties[i].id

            return Response({'properties': properties_data}, status=200)

        except ValueError:
            return Response({'error': 'Les valeurs min_price et max_price doivent être des nombres entiers.'}, status=400)

        except ValidationError as e:
            return Response({'error': str(e)}, status=400)

        except Exception as e:
            return Response({'error': str(e)}, status=500)


@api_view(['GET'])
def properties_advancedSearch(request):
    category_id = request.query_params.get('category_id', None)
    id_service = request.query_params.get('id_service', None)

    try:
        category_instance = Category.objects.get(category_id=category_id)
    except Category.DoesNotExist:
        return Response({"error": "Category not found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        service_instance = Service.objects.get(id_service=id_service)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)

    min_price = Decimal(request.query_params.get('min_price', 0))
    max_price = Decimal(request.query_params.get('max_price', float('inf')))

    properties = PropertyInfo.objects.filter(
        category=category_instance,
        service=service_instance,
        property_prix__gte=min_price,
        property_prix__lte=max_price
    )

    serializer = PropertyInfoSerializer(properties, many=True)
    properties_data = serializer.data

    for i, property_data in enumerate(properties_data):
        property_data['id'] = properties[i].id

    return Response(properties_data, status=status.HTTP_200_OK)



from django.views.decorators.csrf import csrf_exempt
from .models import ReviewStar
import json




@csrf_exempt
def create_review(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        rating = data.get('rating')
        comment = data.get('comment')

        if rating and comment:
            # Créez une nouvelle instance de ReviewStar et enregistrez-la dans la base de données
            review = ReviewStar.objects.create(name=request.user, rating=rating, comment=comment)
            return JsonResponse({'success': True, 'message': 'Review created successfully!'})
        else:
            return JsonResponse({'success': False, 'message': 'Missing required fields.'}, status=400)
    else:
        return JsonResponse({'success': False, 'message': 'Only POST requests are allowed.'}, status=405)


from .models import Property

class TopRatedPropertiesAPIView(APIView):
    def get(self, request):
        top_properties = PropertyInfo.objects.raw("SELECT * FROM userauth_propertyinfo ORDER BY property_prix DESC LIMIT 4")
        serializer = PropertyInfoSerializer(top_properties, many=True)
        return Response(serializer.data)

from rest_framework import generics
from .models import Localisation
from .serializer import LocationSerializer

class LocationListAPIView(generics.ListAPIView):
    queryset = Localisation.objects.all()
    serializer_class = LocationSerializer


from rest_framework.decorators import api_view

@api_view(['GET'])
def get_places_data(request):
    try:
        # Récupère les données de la base de données
        locations = Localisation.objects.all()

        # Formatte les données à renvoyer
        results = []
        for location in locations:
            results.append({
                'emplacement': location.emplacement,
                'latitude': float(location.latitude),
                'longitude': float(location.longitude),

            })

        return Response(results)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

# Dans votre fichier views.py




from rest_framework.decorators import api_view
from .models import Category, Localisation
from .serializer import CategorySerializer, LocationSerializer


@api_view(['GET'])
def categories_and_localisations(request):
    try:
        categories = Category.objects.all()
        localisations = Localisation.objects.all()

        categories_serializer = CategorySerializer(categories, many=True)
        localisations_serializer = LocationSerializer(localisations, many=True)

        return Response({
            'categories': categories_serializer.data,
            'localisations': localisations_serializer.data
        })
    except Exception as e:
        return Response({'error': str(e)}, status=500)



from rest_framework.decorators import api_view
from .serializer import PropertyInfoSerializer

@api_view(['GET'])
def properties_by_location(request, localisation_id):
    try:
        properties = PropertyInfo.objects.filter(localisation_id=localisation_id)
        serialized_properties = PropertyInfoSerializer(properties, many=True).data
        return Response(serialized_properties)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


from django.http import JsonResponse
from .models import Localisation, PropertyInfo

def locations_with_property_count(request):
    # Récupérer toutes les localisations
    locations_with_count = []

    # Boucler à travers chaque localisation
    for location in Localisation.objects.all():
        # Compter le nombre de propriétés associées à cette localisation
        property_count = PropertyInfo.objects.filter(localisation=location).count()

        # Ajouter les informations de localisation et le nombre de propriétés à la liste
        locations_with_count.append({
            'id': location.id,
            'latitude': location.latitude,
            'longitude': location.longitude,
            'property_count': property_count
        })

    # Renvoyer les données au format JSON
    return JsonResponse(locations_with_count, safe=False)



class PropertyLocationAPIView(APIView):
    def get(self, request, property_id):
        property_info = get_object_or_404(PropertyInfo, pk=property_id)
        location = property_info.localisation
        if location:
            return Response({'emplacement': location.emplacement})
        else:
            return Response({'message': 'La propriété ne possède pas de localisation.'}, status=404)


# Dans views.py



#New API
def count_users(request):
    # Compter le nombre d'utilisateurs dans la table User
    user_count = User.objects.count()

    # Retourner le nombre d'utilisateurs dans un objet JSON
    data = {'user_count': user_count}
    return JsonResponse(data)
# Dans views.py
""""
def count_users_by_role(request, role_id):
    try:
        role = Role.objects.get(id=role_id)
    except Role.DoesNotExist:
        return JsonResponse({'error': 'Role does not exist'}, status=404)

    user_count = User.objects.filter(role_id=role).count()
    data = {'user_count': user_count}
    return JsonResponse(data)
# Dans views.py
"""
from django.http import JsonResponse
from .models import Temoinage

def count_temoinages(request):
    temoinage_count = Temoinage.objects.count()
    data = {'temoinage_count': temoinage_count}
    return JsonResponse(data)
# Dans views.py

from django.http import JsonResponse
from .models import PropertyInfo

def count_properties(request):
    property_count = PropertyInfo.objects.count()
    data = {'property_count': property_count}
    return JsonResponse(data)


from rest_framework import generics
from .models import PropertyInfo
from .serializer import ProSerializer

class PropertyListView(generics.ListAPIView):
    queryset = PropertyInfo.objects.all()  # Récupère toutes les propriétés
    serializer_class = ProSerializer



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import PropertyInfo
from .serializer import PropertyInfoSerializer

class MaisonCountAPI(APIView):
    def get(self, request, format=None):
        # Obtenir le nombre de propriétés avec le nom "maison"
        count = PropertyInfo.objects.filter(category__name="maison").count()
        return Response({'maison_count': count}, status=status.HTTP_200_OK)


class appartementCountAPI(APIView):
    def get(self, request, format=None):
        # Obtenir le nombre de propriétés avec le nom "maison"
        count = PropertyInfo.objects.filter(category__name="appartement").count()
        return Response({'appartement_count': count}, status=status.HTTP_200_OK)

class localCountAPI(APIView):
    def get(self, request, format=None):
        # Obtenir le nombre de propriétés avec le nom "maison"
        count = PropertyInfo.objects.filter(category__name="local commercial").count()
        return Response({'local_count': count}, status=status.HTTP_200_OK)

class VillaCountAPI(APIView):
    def get(self, request, format=None):
        # Obtenir le nombre de propriétés avec le nom "maison"
        count = PropertyInfo.objects.filter(category__name="villa").count()
        return Response({'villa_count': count}, status=status.HTTP_200_OK)


from rest_framework.views import APIView
from rest_framework.response import Response
from .models import PropertyInfo, Localisation
from django.db.models import Max

class HighestPriceByLocation(APIView):
    def get(self, request):
        # Récupérer les emplacements uniques
        locations = Localisation.objects.all()

        result = []

        # Pour chaque emplacement, trouver la propriété avec le prix le plus élevé
        for location in locations:
            max_price_property = PropertyInfo.objects.filter(localisation=location).aggregate(Max('property_prix'))
            max_price = max_price_property['property_prix__max']
            property_with_max_price = PropertyInfo.objects.filter(localisation=location, property_prix=max_price).first()

            if property_with_max_price:
                result.append({
                    'emplacement': location.emplacement,
                    'property_titre': property_with_max_price.property_titre,
                    'property_prix': max_price
                })

        return Response(result)

""""
# Dans votre fichier views.py

from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializer import PropertyInfoSerializer

@api_view(['POST'])
def create_property(request):
    if request.method == 'POST':
        serializer = PropertyInfoSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
"""



