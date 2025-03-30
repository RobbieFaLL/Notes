# Django Password Reset Setup and Customizations

## 1. Update `urls.py` to Include Password Reset Views

```python
from django.contrib import admin
from django.urls import path
from pages.views import index, greenproducts, reducecarbon
from management.views import (
    signup,
    login_view,
    Logout,
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,
)

urlpatterns = [
    path('admin/', admin.site.urls, name='Admin'),
    path('', index, name='index'),
    path('greenenergy/', greenproducts, name='greenproducts'),
    path('reducecarbon/', reducecarbon, name='reducecarbon'),
    path('signup/', signup, name='Signup'),
    path('login/', login_view, name='Login'),
    path('logout/', Logout, name='Logout'),
    path('password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', PasswordResetCompleteView.as_view(), name='password_reset_complete'),
]
```

## 2. Password Reset Templates

### `password_reset_complete.html`

```django
{% extends 'base.html' %}

{% block content %}
    <h1>Password Reset Complete</h1>
    <p>Your password has been successfully reset.</p>
    <p><a href="{% url 'Login' %}">Click here to log in</a></p>
{% endblock %}
```

### `password_reset_form.html`

```django
{% extends 'base.html' %}

{% block content %}
    <h1>Reset Your Password</h1>
    <form method="POST">
        {% csrf_token %}
        {{ form.as_p }}
        <input type='submit' value='Reset Password'>
    </form>
{% endblock %}
```

### `password_reset_done.html`

```django
{% extends 'base.html' %}

{% block content %}
    <h1>Password Reset Sent</h1>
    <p>We've emailed you instructions for resetting your password. If you don't receive an email, please check your spam folder or try again.</p>
{% endblock %}
```

### `password_reset_email.html`

```django
{% block content %}
<p>Hello,</p>

<p>You're receiving this email because you requested a password reset for your account. Please click the link below to reset your password:</p>

<p><a href="{{ protocol }}://{{ domain }}{% url 'password_reset_confirm' uidb64=uid token=token %}">Reset Password</a></p>

<p>If you didn't request this, please ignore this email.</p>

<p>Thanks,</p>
<p>The Team</p>
{% endblock %}
```

## 3. Custom Login Form

```python
from allauth.account.forms import LoginForm as AllauthLoginForm

class CustomLoginForm(AllauthLoginForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add custom placeholder or styling
        self.fields['login'].widget.attrs.update({'placeholder': 'Enter your email or username'})
        self.fields['password'].widget.attrs.update({'placeholder': 'Enter your password'})
        # Remove the "Remember Me" checkbox
        if 'remember' in self.fields:
            del self.fields['remember']
```

## 4. Email Backend Configuration

```python
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
```

## 5. Update Default Site Configuration

```python
from django.contrib.sites.models import Site

# Update the default site
site = Site.objects.get(id=1)
site.domain = '127.0.0.1:8000'
site.name = '127.0.0.1'
site.save()
```

## 6. Views (`views.py`)

```python
from django.shortcuts import render, redirect, resolve_url
from allauth.account.forms import SignupForm
from .forms import CustomLoginForm
from allauth.account.views import PasswordResetView
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from django.urls import reverse_lazy
from django.contrib.auth.forms import (
    PasswordResetForm, SetPasswordForm
)
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.core.exceptions import ValidationError, ImproperlyConfigured
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect

UserModel = get_user_model()

# Signup View
def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save(request=request)
            login(request, user)
            return redirect('/')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"Error in {field}: {error}")
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = CustomLoginForm(request.POST, request=request)
        if form.is_valid():
            username = form.cleaned_data.get('login')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('/')
            else:
                messages.error(request, "Invalid credentials")
    else:
        form = CustomLoginForm(request=request)
    return render(request, 'login.html', {'form': form})

def Logout(request):
    logout(request)
    messages.success(request, "You have been logged out.")
    return render(request, 'logout.html')

class PasswordResetConfirmView(FormView):
    form_class = SetPasswordForm
    template_name = "password_reset_confirm.html"
    success_url = reverse_lazy("password_reset_complete")
    token_generator = default_token_generator
    
    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
```

This setup ensures a functional and customizable password reset flow in Django.
