# using-openssl-keys
## Comandos Necesarios

### Encriptar
~~~
openssl rsautl -in txt.txt -out opensll.enc -pkcs -inkey private.pem -encrypt
~~~

### Desencriptar
~~~
openssl rsautl -in encrypt.enc -out t.txt -pkcs -inkey private.pem -decrypt
~~~

Si al utilizar alguna de estos comandos pide una contraseña introduzca: 'cfabrica46'
