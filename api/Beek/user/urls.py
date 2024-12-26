from django.urls import path
from user.views import (UsersListView, SignupView, ForgotPasswordView,
                        RestrictUserAccountView, UserProfileView, DeleteAccountView, LoginView,
                        CreateSubscription, SetPasswordView, StripeWebhooks, CancelSubscription,
                        AdminPasswordResetView, UserPasswordResetView, UserChangePasswordView,
                        RefreshTokenView, ValidateActivationToken, LogoutView, ResendVerificationEmail,
                        UserReportListView, UserReportMetrics, ExportUserReportView, UserAPIUsageReportListView,
                        ApiUsageReportMetrics, ExportUserAPIUsageReportView, UserAPIUsageDetailsListView)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='auth_logout'),
    path('login/refresh/', RefreshTokenView.as_view(), name='token_refresh'),

    path('admin/users/', UsersListView.as_view(), name='user_list'),
    path('admin/users/restrict/',
         RestrictUserAccountView.as_view(), name='restrict_account'),

    path('register/', SignupView.as_view(), name='user_signup'),
    path('set-password/', SetPasswordView.as_view(), name='set_password'),
    path('validate-token/', ValidateActivationToken.as_view(), name='validate-token'),
    path('resend-verification-email/', ResendVerificationEmail.as_view(), name='resend-verification-email'),

    # Endpoint for a user to request a password reset link (forgot password)
    path('password/forgot/', ForgotPasswordView.as_view(),
         name='user-password-forgot'),

    # Endpoint for an admin to request a password reset link for a user
    path('admin/users/password/reset-email/', AdminPasswordResetView.as_view(),
         name='admin-users-password-reset'),

    # Endpoint for a user to reset their password using the reset link
    path('password/reset/', UserPasswordResetView.as_view(),
         name='user-password-reset'),

    # Endpoint for a logged-in user to change their password from their profile
    path('profile/password/change/', UserChangePasswordView.as_view(),
         name='user-profile-password-change'),

    path('profile/', UserProfileView.as_view(), name='profile'),
    path('delete-account/', DeleteAccountView.as_view(), name='delete-account'),
    path('create-subscription/', CreateSubscription.as_view(),
         name='create-subscription'),
    path('subscription/cancel/', CancelSubscription.as_view(),
         name='subscription-cancel'),
    path('webhook/stripe/', StripeWebhooks.as_view(), name='webhook-stripe'),

    path('admin/reports/users/', UserReportListView.as_view(), name='user-report-list'),
    path('admin/reports/users/metrics/', UserReportMetrics.as_view(), name='admin-reports-users-metrics'),
    path('admin/reports/users/export/', ExportUserReportView.as_view(), name='export-user-report'),
    path('admin/reports/api-usage/', UserAPIUsageReportListView.as_view(), name='user-report-list'),
    path('admin/reports/api-usage/metrics/', ApiUsageReportMetrics.as_view(), name='admin-reports-api-usage-metrics'),
    path('admin/reports/api-usage/export/', ExportUserAPIUsageReportView.as_view(), name='export-user-api-report'),
    path('admin/reports/api-usage/details/', UserAPIUsageDetailsListView.as_view(), name='user-api-usage-details'),
]
