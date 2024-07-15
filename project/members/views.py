# views.py

from django.core.mail import send_mail,EmailMessage
from django.shortcuts import render
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.conf import settings
from rest_framework.response import Response

from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from .serialiser import UserSerializer
from .models import User
import jwt
from rest_framework import status
import datetime

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from rest_framework.views import APIView

@csrf_exempt
def send_email_varification(email,token):
  
    
    url = f"http://127.0.0.1:8000/api/token/{token}/email/{email}"  # This should be dynamically generated based on your requirements

    email_content = render_to_string('members/email_template.html', {'url': url})

    email_message = EmailMessage(
        subject='Subject of your email',
        body=email_content,
        from_email=settings.EMAIL_HOST_USER,
        to=[email],
    )
    email_message.content_subtype = 'html'  # Set the email content type to HTML

    email_message.send(fail_silently=False)

    return HttpResponse('Email sent successfully!')


def Guest_user(request, name):
    # You can send the name to the backend or process it here

    # user = User.objects.filter(sid=name).first()
    # conditions=user.conditions

    response_data = {
        'message': f'Hello, {name}!'
    }
    return JsonResponse(response_data,safe=False)

def Mail_verify(request, token,email):
    # You can send the name to the backend or process it here
    print(token)
    if not token:
        return Response({'error': 'Token is missing'}, status=400)

    try:
        payload = jwt.decode(token, 'secret', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return Response({'error': 'Token is expired'}, status=401)
    except jwt.InvalidTokenError:
        return Response({'error': 'Invalid token'}, status=401)

    user = User.objects.filter(uid=payload.get('gid')).first()
    if not user:
        return Response({'error': 'User not found'}, status=404)


    if email not in user.contact_mails:
        user.contact_mails.append(email)
        user.save()
    context = {
        'email': email
    }
    return render(request, 'verify_done.html', context)


class Sendmail(APIView):
    def post(self, request):
        email = request.data.get('email')
        token = request.data.get('token')  # Use get method to avoid KeyError
        if not token:
            return Response({'error': 'Token is missing'}, status=400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token is expired'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=401)

        user = User.objects.filter(uid=payload.get('gid')).first()
        if not user:
            return Response({'error': 'User not found'}, status=404)

        send_email_varification(email,token)
        return Response("send")


class Guest_med_0(APIView):
    def post(self, request):
        sid = request.data.get('sid')
       
        if not sid:
            return Response({'error': 'Token is missing'}, status=400)

        user = User.objects.filter(sid=sid).first()
        if not user:
            return Response({'error': 'User not found'}, status=404)
        
        serializer = UserSerializer(user)
        return Response(serializer.data)
    

@csrf_exempt
def send_email_notify_loc(latitude,longitude,contact):
  
    

    email_content = render_to_string('members/notify_loc.html', {'latitude': latitude,
        'longitude': longitude})

    email_message = EmailMessage(
        subject='Subject of your email',
        body=email_content,
        from_email=settings.EMAIL_HOST_USER,
        to=contact,
    )
    email_message.content_subtype = 'html'  # Set the email content type to HTML

    email_message.send(fail_silently=False)

    return HttpResponse('Email sent successfully!')


class Send_notification_location(APIView):
    def post(self, request):
        latitude = request.data.get('latitude')
        longitude = request.data.get('longitude')  # Use get method to avoid KeyError
        contact = request.data.get('contact') 
       
        send_email_notify_loc(latitude,longitude,contact)
        return Response("send")



@csrf_exempt
def send_email_request_med1(contact,sid):
  
    
    url = f"http://127.0.0.1:8000/api/med_1/{sid}" 
    email_content = render_to_string('members/send_req_mes1.html', {'url': url})

    email_message = EmailMessage(
        subject='Subject of your email',
        body=email_content,
        from_email=settings.EMAIL_HOST_USER,
        to=contact,
    )
    email_message.content_subtype = 'html'  # Set the email content type to HTML

    email_message.send(fail_silently=False)

    return HttpResponse('Email sent successfully!')


class send_request(APIView):
    def post(self, request):
      
        contact = request.data.get('contact') 
        sid = request.data.get('sid') 
        print(sid)
        send_email_request_med1(contact,sid)
        return Response("send")

def med_1_req_grant(request, name):
    # You can send the name to the backend or process it here

    # user = User.objects.filter(sid=name).first()
    # conditions=user.conditions
    user=User.objects.filter(sid=name).first()
    if user is None:
        return Response({'error': 'User not found!'}, status=404)
    
    if "med1" not in user.conditions:
        user.conditions.append("med1")
        user.save()

    return render(request, 'grant_acess.html')

######################################################################################################

class RegisterView(APIView):
    def post(self, request):

        serializer = UserSerializer(data=request.data)
        print(request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            # Customize the error message as per your requirement
            error_message = "Invalid input. Please check your details."
            # Return a success response with a custom error message
            return Response({"error": error_message}, status=status.HTTP_200_OK)

class LoginView(APIView):
    def post(self, request):
       
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'error': 'Email and password are required!'}, status=400)

        user = User.objects.filter(email=email).first()
        
        if user is None:
            return Response({'error': 'User not found!'}, status=404)

        if (password==user.password):
            gid_str = str(user.uid)
            payload = {
                'gid': gid_str,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=120),
                'iat': datetime.datetime.utcnow()
            }

            token = jwt.encode(payload, 'secret', algorithm='HS256')
            # print(token)
            response = Response({'token': token})
            return response
        else:
            return Response({'error': 'Incorrect password!'}, status=401)


class LoginViewgmail(APIView):
    def post(self, request):
       
        email = request.data.get('gid')
        


        user = User.objects.filter(gid=email).first()

        if user is None:
            return Response({'error': 'User not found!'}, status=404)

        if (user):
            print("gid")
            gid_str = str(user.uid)
            payload = {
                'gid': gid_str,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                'iat': datetime.datetime.utcnow()
            }

            token = jwt.encode(payload, 'secret', algorithm='HS256')

            print(token)
            return Response({'token': token},status=200)
        else:
            return Response({'error': 'Incorrect password!'}, status=401)



class UserView(APIView):
    def post(self, request):
        token = request.data.get('token')  # Use get method to avoid KeyError
        if not token:
            return Response({'error': 'Token is missing'}, status=400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token is expired'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=401)

        user = User.objects.filter(uid=payload.get('gid')).first()
        if not user:
            return Response({'error': 'User not found'}, status=404)

        serializer = UserSerializer(user)
        return Response(serializer.data)

class User_id(APIView):
    def post(self, request):
        token = request.data.get('token')  # Use get method to avoid KeyError
        if not token:
            return Response({'error': 'Token is missing'}, status=400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token is expired'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=401)


        return Response(payload.get('gid'))

class Delete_user(APIView):
    def post(self, request):
        token = request.data.get('token')  # Use get method to avoid KeyError
        if not token:
            return Response({'error': 'Token is missing'}, status=400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token is expired'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=401)

        user = User.objects.filter(uid=payload.get('gid')).first()
        if not user:
            return Response({'error': 'User not found'}, status=404)
        
        user.delete()
        return Response({'message': 'Object deleted successfully'}, status=status.HTTP_204_NO_CONTENT)



class Add_bucket(APIView):
    def post(self, request):

        token = request.data.get('token')
        bucket=request.data.get('data')
        cond=request.data.get('condition')
        # print(bucket)
        if not token:
            return Response({'error': 'Token is missing'}, status=400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token is expired'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=401)

        user = User.objects.filter(uid=payload.get('gid')).first()
        print(user)
        if not user:
            return Response({'error': 'User not found'}, status=404)

        if not user:
            return Response({'error': 'User not found'}, status=404)

       

        if cond == 1:
            user.medicine_1.append(bucket)
        elif cond == 0:
            user.medicine_0.append(bucket)
        elif cond == 2:
            user.medicine_2.append(bucket)

        user.save()

        # serializer = UserSerializer(user)
        return Response("ok")
       
class Add_condition(APIView):
    def post(self, request):

        token = request.data.get('token')
        bucket=request.data.get('bucket')
        
        if not token:
            return Response({'error': 'Token is missing'}, status=400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token is expired'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=401)

        user = User.objects.filter(uid=payload.get('gid')).first()
        print(user,bucket)
        if not user:
            return Response({'error': 'User not found'}, status=404)

        if not user:
            return Response({'error': 'User not found'}, status=404)



        user.curlocation=bucket
        user.save()

        # serializer = UserSerializer(user)
        return Response("ok")
       
       


class Delete_medical_tElement(APIView):
    def post(self, request):
        token = request.data.get('token')
        element_to_delete = request.data.get('bucket')  # Assuming you send the element itself
        
        if not token:
            return Response({'error': 'Token is missing'}, status=400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token is expired'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=401)

        user = User.objects.filter(uid=payload.get('gid')).first()

        if not user:
            return Response({'error': 'User not found'}, status=404)

        if not user.bucket:
            return Response({'error': 'Bucket is empty'}, status=200)
        print(element_to_delete)
        if element_to_delete in user.bucket:
            user.bucket.remove(element_to_delete)
            user.save()
            return Response({'message': 'Element deleted successfully'}, status=200)
        else:
            return Response({'error': 'Element not found in the bucket'}, status=200)
        


class Update_date_in__med_list(APIView):
    def post(self, request):
        
        token = request.data.get('token')
        element_to_update = request.data.get('bucket')  # Assuming you send the element itself
        date=request.data.get('date')
        print(date,element_to_update)
        if not token:
            return Response({'error': 'Token is missing'}, status=400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token is expired'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=401)

        user = User.objects.filter(uid=payload.get('gid')).first()

        if not user:
            return Response({'error': 'User not found'}, status=404)

        if not user.bucket:
            return Response({'error': 'Bucket is empty'}, status=200)
   
        updated = False
        for idx, item in enumerate(user.bucket):
            if (item['City'] == element_to_update['City'] and
                item['State'] == element_to_update['State'] and
                item['District'] == element_to_update['District']):
                user.bucket[idx]['Date'] = date
                updated = True
                break
        
        if updated:
            user.save()
            return Response({'message': 'Element updated successfully'}, status=200)
        else:
            return Response({'error': 'Element not found in the bucket'}, status=404)



class Update_password(APIView):
    def post(self, request):

        token = request.data.get('token')
        name=request.data.get('name')
        spass = request.data.get('spass')
        isused = request.data.get('isused')
        phone = request.data.get('phone')

        if not token:
            return Response({'error': 'Token is missing'}, status=400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token is expired'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=401)

        user = User.objects.filter(uid=payload.get('gid')).first()
        if not user:
            return Response({'error': 'User not found'}, status=404)

        if spass:
            user.spass = spass
        if isused:
            user.isused = isused
        
        if phone:
            user.phone=phone

        if name:
            user.name=name

        user.save()
        serializer = UserSerializer(user)
        return Response(serializer.data)
       
        

