from django.urls import path
from . import views

app_name = 'monitor'

urlpatterns = [
    path('', views.DashboardView.as_view(), name='dashboard'),
    path('traffic/', views.TrafficMonitoringView.as_view(), name='traffic'),
    path('alerts/', views.AlertHistoryView.as_view(), name='alerts'),
    path('reports/', views.ReportsView.as_view(), name='reports'),
    path('query/', views.QueryAnalysisView.as_view(), name='query_analysis'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('users/', views.UserManagementView.as_view(), name='user_management'),
    path('reports/pdf/', views.ExportPDFView.as_view(), name='export_pdf'),
    path('api/traffic/', views.TrafficAPIView.as_view(), name='traffic_api'),
]
