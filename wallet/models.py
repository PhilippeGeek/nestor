import base64
import random
import string

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, MD5
from Crypto.PublicKey import RSA
from datetime import timedelta, datetime
from django.utils import timezone
from django.contrib.auth.models import User
from django.db import models
from django.utils.translation import ugettext_lazy as _


class Data(models.Model):
    class Meta:
        verbose_name = _('Donnée')

    owner = models.ForeignKey(User, related_name='datas', verbose_name=_('propriétaire'))
    content = models.BinaryField(verbose_name=_('contenu'))
    key = models.ForeignKey('Key', verbose_name=_('clef'))
    name = models.CharField(verbose_name=_('nom'), max_length=250, default='', null=True)
    comment = models.TextField(verbose_name=_('commentaires'), default='', null=True, blank=True)

    def update_content(self, new_content):
        self.content = self.key.encrypt(new_content.encode())
        self.save()

    def read_content(self, password):
        return self.key.decrypt(self.content, password).decode('utf_8')

    def __str__(self):
        return "{} - {} - {}".format(self.owner, self.key.key_id_small, self.name)


class Key(models.Model):
    class Meta:
        verbose_name = _('Clef')

    owner = models.ForeignKey(User, related_name='keys', verbose_name=_('propriétaire'))
    encrypted_password = models.TextField(verbose_name=_('mot de passe'))
    encrypted_private_key = models.TextField(verbose_name=_('clef privé'))
    public_key = models.TextField(verbose_name=_('clef publique'))
    __password = ''

    @classmethod
    def create(cls, owner, password):
        key = cls(owner=owner)
        if key.owner is None:
            raise RuntimeError('Can not create Key for an unknown user')
        key.__password = Key._generate_password()
        rsa_key = RSA.generate(2048)
        key.public_key = rsa_key.publickey().exportKey().decode('utf_8')
        key.encrypted_private_key = rsa_key.exportKey(passphrase=key.__password).decode('utf_8')
        key.update_user_password(password)
        key.save()
        return key

    def encrypt(self, data):
        key = RSA.importKey(self.public_key)
        return PKCS1_OAEP.new(key).encrypt(data)

    def decrypt(self, data, user_password):
        self.clean_in_memory()
        self._load_encryption_password(user_password)
        if self.__password == '':
            raise RuntimeError('No password loaded!')
        key = RSA.importKey(self.encrypted_private_key, self.__password)
        return PKCS1_OAEP.new(key).decrypt(data)

    def update_user_password(self, new_password, old_password=None):
        """
        Update password used by user to decrypt the real private key password
        :param new_password:string The new user password which will be used in future
        :param old_password:string The old user password to decrypt the old password
        """
        if old_password is not None:
            self._load_encryption_password(old_password)
        if self.__password == '':
            raise RuntimeError('No password loaded!')
        password_digest = SHA256.new(new_password.encode()).digest()
        encryption = AES.new(password_digest)
        self.encrypted_password = base64.encodebytes(encryption.encrypt(self.__password)).decode('utf_8')

    def _load_encryption_password(self, user_password: string) -> None:
        """
        Load in memory the private key password for this key
        :param user_password: string
        """
        if self.__password == '':
            password_digest = SHA256.new(user_password.encode()).digest()
            encryption = AES.new(password_digest)
            encrypted_password = base64.decodebytes(self.encrypted_password.encode())
            self.__password = encryption.decrypt(encrypted_password).decode('utf_8')

    def clean_in_memory(self):
        self.__password = ''

    @property
    def key_id(self):
        return MD5.new(RSA.importKey(self.public_key).exportKey('DER')).hexdigest().upper()

    @property
    def key_id_small(self):
        return self.key_id[-7:]

    def __str__(self):
        return "{} ({})".format(self.owner, self.key_id)

    @staticmethod
    def _generate_password():
        return ''.join(
            random.SystemRandom().choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(256))


class SessionKey(models.Model):

    session_id = models.CharField(max_length=20)
    client_public_key = models.TextField()
    server_private_key = models.TextField()
    user = models.ForeignKey(User)
    created_at = models.DateTimeField(auto_now_add=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__client_key = None
        self.__server_key = None

    @classmethod
    def create(cls, user):
        session = cls(user=user)
        client_key = RSA.generate(1024)
        server_key = RSA.generate(1024)
        session.client_public_key = client_key.publickey().exportKey()
        session.server_private_key = server_key.exportKey()
        session.session_id = session.server_key_id[:10]+session.client_key_id[:10]
        session.__client_key = client_key
        session.__server_key = server_key
        return session

    def encrypt_for_client(self, data):
        key = RSA.importKey(self.client_public_key)
        return PKCS1_OAEP.new(key).encrypt(data)

    def decrypt_from_client(self, data):
        key = RSA.importKey(self.server_private_key)
        return PKCS1_OAEP.new(key).decrypt(data)

    @property
    def valid(self):
        return timezone.now() - timedelta(days=1) < self.created_at

    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
        self.__client_key = None
        super().save(force_insert, force_update, using, update_fields)

    @property
    def client_private_key(self):
        if self.__client_key is not None:
            return self.__client_key
        else:
            raise Exception('Can not get private key of client after save into db')

    @property
    def client_key_id(self):
        return MD5.new(RSA.importKey(self.client_public_key).exportKey('DER')).hexdigest().upper()

    @property
    def server_key_id(self):
        return MD5.new(RSA.importKey(self.server_private_key).publickey().exportKey('DER')).hexdigest().upper()

    def __str__(self):
        return "{} ({})".format(self.user, self.session_id)
