from django.urls import path, include
from . import views

urlpatterns = [
    path('',                        views.index,             name='index'),
    path('login/',                  views.login_view,        name='login'),
    path('logout/',                 views.logout_view,       name='logout'),
    path('analyze/',                views.analyze,           name='analyze'),
    path('dashboard/<int:run_id>/', views.dashboard,         name='dashboard'),
    path('download/<int:run_id>/',  views.download_results,  name='download_results'),
    path('malware/',                include('malware_views.urls')),
    path('intel/',                  include('threatintel.urls')),
]
