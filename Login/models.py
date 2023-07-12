from django.db import models

class packet(models.Model):

    Source = models.TextField()
    Destination = models.TextField()
    Protocol = models.TextField()

# Create your models here.
