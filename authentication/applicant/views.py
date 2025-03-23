from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import EmailMessage
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse, reverse_lazy
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.core.exceptions import ObjectDoesNotExist

from .forms import RegistrationForm  # Import your custom form

UserModel = get_user_model()


# Home Page
def homepage(request):
    return render(request, 'homepage.html')


# User Login
def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)

        if user:
            if user.is_active:
                login(request, user)
                messages.success(request, "Login successful!")
                return redirect('homepage')
            messages.error(request, "Your account is not verified. Please check your email.")
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, 'login.html')


# User Logout
@login_required
def user_logout(request):
    logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('login')


# User Registration (with email verification)
def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Deactivate account until email is verified
            user.save()

            # Generate verification email
            current_site = get_current_site(request)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            activation_link = f"{request.scheme}://{current_site.domain}/activate/{uid}/{token}/"

            mail_subject = "Activate Your Account"
            message = render_to_string('email_verification.html', {
                'user': user,
                'activation_link': activation_link,
            })

            email = EmailMessage(mail_subject, message, to=[user.email])
            email.content_subtype = "html"
            email.send(fail_silently=False)

            messages.success(request, "Registration successful! Please check your email to verify your account.")
            return redirect('login')

    else:
        form = RegistrationForm()

    return render(request, 'register.html', {'form': form})


# Email Verification View
def activate_account(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = UserModel.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, ObjectDoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Your account has been verified! You can now log in.")
        return redirect('login')

    messages.error(request, "Activation link is invalid or has expired.")
    return redirect('register')


# Admin Login View
def admin_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = UserModel.objects.get(email=email)
            if user.is_staff:
                authenticated_user = authenticate(request, username=user.username, password=password)
                if authenticated_user:
                    login(request, authenticated_user)
                    messages.success(request, "Admin login successful!")
                    return redirect('admin_dashboard')  # Update this with your admin dashboard URL name
                messages.error(request, "Invalid credentials.")
            else:
                messages.error(request, "You do not have admin access.")
        except ObjectDoesNotExist:
            messages.error(request, "Admin not found.")

    return render(request, 'admin_login.html')


# Forgot Password (Custom View)
# Forgot Password (Custom View)
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = UserModel.objects.get(email=email)

            # Generate password reset link
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_url = request.build_absolute_uri(reverse_lazy('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token}))

            print(f"Generated reset link: {reset_url}")  # Debugging: Check if the link is being generated

            # Render email template
            mail_subject = "Password Reset Request"
            message = render_to_string('password_reset_email.txt', {
                'user': user,
                'reset_url': reset_url,  # Ensure this is passed correctly
            })

            # Send email as plain text
            email_message = EmailMessage(mail_subject, message, to=[email])
            email_message.send(fail_silently=False)

            messages.success(request, "An email has been sent with instructions to reset your password.")
            return redirect('password_reset_done')

        except UserModel.DoesNotExist:
            messages.error(request, "No account found with this email.")

    return render(request, 'forgot_password.html')


# Password Reset Done View
def password_reset_done(request):
    return render(request, 'password_reset_done.html')


# Django Built-in Password Reset (Custom View)
class CustomPasswordResetView(PasswordResetView):
    template_name = 'forgot_password.html'
    email_template_name = 'password_reset_email.html'
    subject_template_name = 'password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        email = form.cleaned_data.get('email')
        if not UserModel.objects.filter(email=email).exists():
            messages.error(self.request, "No account found with this email.")
            return redirect('password_reset')

        messages.success(self.request, "If the email exists, a reset link has been sent.")
        return super().form_valid(form)


# Password Reset Confirmation
class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')
