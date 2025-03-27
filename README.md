from django.shortcuts import render
from allauth.account.forms import SignupForm, LoginForm
from django.contrib.auth import login
from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth import login as auth_login

# Signup View
def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save(request=request)
            user.backend = 'django.contrib.auth.backends.ModelBackend'
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
        form = LoginForm(request.POST, request=request)
        if form.is_valid():
            # Instead of form.get_user(), authenticate using the cleaned data
            username = form.cleaned_data.get('login')  # field name might vary
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                auth_login(request, user)
                return redirect('/')
            else:
                messages.error(request, "Invalid credentials")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"Error in {field}: {error}")
    else:
        form = LoginForm(request=request)
    return render(request, 'login.html', {'form': form})

def Logout(request):
    logout(request)
    messages.success(request, "You have been logged out.")
    return render(request, 'logout.html')
