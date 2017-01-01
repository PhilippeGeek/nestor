from django.contrib import admin

# Register your models here.
from wallet import models


@admin.register(models.Key)
class KeyResourceAdmin(admin.ModelAdmin):
    pass


@admin.register(models.Data)
class DataResourceAdmin(admin.ModelAdmin):
    pass
