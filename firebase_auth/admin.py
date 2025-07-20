from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import FirebaseUser

@admin.register(FirebaseUser)
class FirebaseUserAdmin(UserAdmin):
    """Admin interface for FirebaseUser model."""
    
    # Fields to display in the list view
    list_display = (
        'username', 
        'email', 
        'firebase_uid', 
        'first_name', 
        'last_name', 
        'role', 
        'is_active', 
        'date_joined',
        'created_at'
    )
    
    # Fields that can be searched
    search_fields = (
        'username', 
        'email', 
        'first_name', 
        'last_name', 
        'firebase_uid'
    )
    
    # Fields to filter by
    list_filter = (
        'role', 
        'is_active', 
        'is_staff', 
        'is_superuser', 
        'date_joined',
        'created_at'
    )
    
    # Fields to display in the detail view
    fieldsets = (
        (None, {
            'fields': ('username', 'password')
        }),
        ('Personal info', {
            'fields': ('first_name', 'last_name', 'email', 'phone_number')
        }),
        ('Firebase Info', {
            'fields': ('firebase_uid', 'profile_picture_url'),
            'classes': ('collapse',)
        }),
        ('Permissions', {
            'fields': (
                'is_active', 
                'is_staff', 
                'is_superuser',
                'role',
                'groups', 
                'user_permissions'
            ),
            'classes': ('collapse',)
        }),
        ('Important dates', {
            'fields': ('last_login', 'date_joined', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    # Fields to display when adding a new user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role'),
        }),
    )
    
    # Fields that are read-only
    readonly_fields = ('created_at', 'updated_at', 'date_joined', 'last_login')
    
    # Ordering
    ordering = ('-date_joined',)
    
    # Number of items per page
    list_per_page = 25
    
    # Actions
    actions = ['activate_users', 'deactivate_users', 'make_admin', 'make_user']
    
    def activate_users(self, request, queryset):
        """Activate selected users."""
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} users were successfully activated.')
    activate_users.short_description = "Activate selected users"
    
    def deactivate_users(self, request, queryset):
        """Deactivate selected users."""
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} users were successfully deactivated.')
    deactivate_users.short_description = "Deactivate selected users"
    
    def make_admin(self, request, queryset):
        """Make selected users admin."""
        updated = queryset.update(role='admin')
        self.message_user(request, f'{updated} users were successfully made admin.')
    make_admin.short_description = "Make selected users admin"
    
    def make_user(self, request, queryset):
        """Make selected users regular users."""
        updated = queryset.update(role='user')
        self.message_user(request, f'{updated} users were successfully made regular users.')
    make_user.short_description = "Make selected users regular users"
