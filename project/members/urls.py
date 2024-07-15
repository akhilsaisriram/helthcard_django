from django.urls import path
from .views import *

urlpatterns = [
    path('send-email', Sendmail.as_view()),
    path('med_1/<str:name>/', med_1_req_grant, name='med_1_req_grant'),
    path('token/<str:token>/email/<str:email>/', Mail_verify, name='Mail_verify'),
    path('Send_notification_location',Send_notification_location.as_view()),
    path('Send_acess_req',send_request.as_view()),
    path('Guest_med_0',Guest_med_0.as_view()),
    path('register', RegisterView.as_view()),
    path('login', LoginView.as_view()),
    path('gmaillogin', LoginViewgmail.as_view()),
    path('user', UserView.as_view()),
    path('deleter_user',Delete_user.as_view()),
    path('Update',Update_password.as_view()),
    path('update_list',Update_date_in__med_list.as_view()),
    path('Add_bucket',Add_bucket.as_view()),
    path("Delete_medical_tElement",Delete_medical_tElement.as_view()),
    path("Add_condition",Add_condition.as_view())

]