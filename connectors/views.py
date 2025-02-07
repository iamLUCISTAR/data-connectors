from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import login, authenticate
from django.views.generic import TemplateView
from .forms import CustomUserCreationForm
from django.shortcuts import redirect, render

class SignUpView(TemplateView):
    template_name = 'connectors/signup.html'

    def get(self, request):
        form = CustomUserCreationForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            return redirect('landing')  # Redirect to the home page after signup
        return render(request, self.template_name, {'form': form})


class LandingPageView(LoginRequiredMixin, TemplateView):
    template_name = 'connectors/landing.html'

    def get_context_data(self, **kwargs):
        # Pass the logged-in user to the context
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user  # Ensure user is available in the template context
        return context

class GooglePageView(LoginRequiredMixin, TemplateView):
    template_name = 'connectors/google.html'

    def get_context_data(self, **kwargs):
        # Pass the logged-in user to the context
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user  # Ensure user is available in the template context
        return context

class MicrosoftPageView(LoginRequiredMixin, TemplateView):
    template_name = 'connectors/microsoft.html'

    def get_context_data(self, **kwargs):
        # Pass the logged-in user to the context
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user  # Ensure user is available in the template context
        return context