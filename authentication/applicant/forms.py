from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model

User = get_user_model()  # Use your CustomUser model

class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['reg_number', 'email', 'full_name', 'password1', 'password2']  # Adjust fields to match CustomUser

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.full_name = self.cleaned_data['full_name']  # CustomUser has full_name
        user.set_password(self.cleaned_data['password1'])

        if commit:
            user.save()
        return user
