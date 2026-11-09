from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('search/', views.search, name='search'),
    path('analyze/', views.analyze, name='analyze'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('report/new/', views.ReportCreateView.as_view(), name='report_create'),
    path('report/<int:pk>/', views.ReportDetailView.as_view(), name='report_detail'),
    path('report/<int:pk>/edit/', views.ReportUpdateView.as_view(), name='report_edit'),
    path('report/<int:pk>/delete/', views.ReportDeleteView.as_view(), name='report_delete'),
    path('report/<int:pk>/vote/', views.vote, name='vote'),
    path('report/<int:pk>/comment/', views.add_comment, name='add_comment'),
    path('types/<slug:slug>/', views.scam_type_detail, name='scam_type'),
    path('history/clear/', views.clear_history, name='clear_history'),
    path('api/check/', views.api_check, name='api_check'),
]
