# Trabalho 5 - Broker MQTT com TLS: Mosquitto

## Comunicação segura com Mosquitto

Verificar se o **broker** mosquitto está respondendo corretamente na porta **1883/TCP** (utilize dois terminais de comando):

Use **mosquitto_sub** para assinar o tópico test:
`mosquitto_sub -h localhost -t test`

Publique uma mensagem no tópico test com:
`mosquitto_pub -h localhost -t test -m "hello world"`

### Configurar suporte **SSL/TLS** para Mosquitto

. **Descrição**
O **broker** mosquitto fornece suporte **SSL** para conexões de rede criptografadas e à autenticação.

### Para gerar os certificados

. Comandos **openssl** que podem ser usados para gerar certificados. 
O asciicast "Generating a TLS certificate for mosquitto (Links para um site externo.)" em https://asciinema.org/a/201826
apresenta uma idéia  completa de como usar os comandos.

. **Root ou Autoridade Certificadora (CA)**
Para teste, é possível gerar o próprio certificado e a chave de autoridade de certificação.

`
openssl req -new -x509 -days <duração> -extensions v3_ca -keyout ca.key -out ca.crt
onde duração (para um ano) = 365
`

> ou alternativamente:
> `openssl genrsa -des3 -out ca.key 2048`
> `openssl req -new -x509 -nodes -key ca.key -days 1826 -out ca.crt`

## MQTT Servidor (broker)

Esse procedimento gerará uma chave privada para o servidor **mosquitto**, bem como uma 
solicitação de assinatura de certificado, onde será necessário inserir detalhes 
como por exemplo o nome do host e informações da organização, antes de enviá-lo para 
uma **CA** para aprovação.

Gere a chave de servidor sem criptografia.
`openssl genrsa -out myserver.key 2048`

Gere uma solicitação de assinatura de certificado para enviar à CA.
`openssl req -new -key myserver.key -out myserver.csr`

  Nota: Quando for solicitado o **CN** (Common Name ou Nome Comum), informe o endereço IP,
        ou nome do host servidor (**broker**), ou o nome do domínio completo.

Para teste, no entanto, não é necessário enviar o arquivo .csr para uma CA externa 
já que é suficiente assiná-lo com a chave da CA gerada anteriormente.
Então, usa-se a chave da CA para verificar e assinar o certificado do servidor.

`openssl x509 -req -in myserver.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out myserver.crt -days <duração>`

> Caso se detecte a necessidade de converter para o formato PEM
>`openssl x509 -inform DER -outform PEM -in myserver.crt -out myserver.pem`

**Obs.**: O aquivo **ca.key** é usado somente para criar um novo certificado para
o servidor ou para um cliente.

Os três arquivos de interesse para o mosquitto são o **ca.crt, 
myserver.crt e myserver.key:**
  ```
/etc/mosquitto/ca_certificates/{ca.crt, ca.key}
  /etc/mosquitto/certs/{myserver.crt, myserver.key}
```

Consulte o conteúdo e as instruções de **mosquitto.conf**, que é o arquivo de configuração 
do **mosquitto** (Veja mais em https://mosquitto.org/man/mosquitto-conf-5.html (Links para um site externo.)).

Edite o arquivo de configuração do mosquitto (observe os comentários no próprio arquivo):
`sudo nano /etc/mosquitto/mosquitto.conf`

. . .
Default listener
**É o endereço ip da sua máquina, ou então**
`bind_address 192.168.1.xyz`

**Você pode utilizar o nome da sua placa**
`bind_interface eth0`
`port 1883`
. . .

Default listener
**MQTT over SSL/TLS on port 8883**
`listener 8883 0.0.0.0`

```
cafile   /etc/mosquitto/ca_certificates/ca.crt
keyfile  /etc/mosquitto/certs/myserver.key
certfile /etc/mosquitto/certs/myserver.crt
tls_version tlsv1.2
```

> If false, a device will check Mosquitto certificate, but Mosquitto won't check
> the device counterparts.
> If true, both checks are performed (2-way TLS)
> 
> É necessário testar (com false) a configuração adequada
> `require_certificate true`

> Certificate Common Name field will be used as username.
> Thus, a device with 'CN=abc1' will have a 'user abc1' entry in Mosquitto's ACL
> use_identity_as_username true
> 
> Permission list file
> `acl_file /etc/mosquitto/certs/access.acl`

### Persistence
```
persistence true
persistence_location /var/log/mosquitto/
persistence_file mosquitto.db
```

### Logging
```
log_dest file /var/log/mosquitto.log
log_type error
log_type warning
log_type notice
```

Verifique se o **broker mosquitto** identifica todas as suas instruções de configuração e inicia corretamente:
`mosquito -c /etc/mosquitto/mosquitto.conf`

A sequencia **Ctrl + C** interrompe essa execução.

Se ocorrer **erro**: consulte o arquivo `/var/log/mosquitto.log` para obter mais detalhes.

Reinicie o serviço do **broker mosquitto**
`sudo systemctl restart mosquitto`

Verifique o conteúdo do certificado do broker 
`openssl x509 -in /etc/mosquitto/certs/myserver.crt -text -noout`

### MQTT Cliente

O cliente precisa do arquivo de certificado da **CA** (**ca.crt**) gerado 
anteriormente (**broker** e clientes devem utilizar a mesma CA).

Gere uma chave de cliente.
`openssl genrsa -out client.key 2048`

Gere uma solicitação de assinatura de certificado para enviar à **CA** 
(ou assiná-lo localmente).
`openssl req -new -key client.key -out client.csr`

> Nota: Neste procedimento serão solicitadas algumas informações, a mais importante
>           é o Common Name (nome comum). Este nome pode ser usado pelo **broker** para 
>           identificar o cliente no lugar de um username (nome de usuário).

Este arquivo de certificado (**.crt**) seria enviado para a **CA** externa, entretanto para 
teste é possível assinar essa solicitação com a chave da própria **CA** local e 
criar o certificado do cliente.
`openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days <duração>`

Para o cliente utilizar certificado são necessários três arquivos:
. **ca.crt** - O certificado da CA
. **client.crt** - O arquivo de certificado do cliente
. **client.key** - A chave privada do cliente

Utilize dois terminais de comandos distintos para executar o procedimento e então, teste a publicação em uma conexão segura com o comando:
`mosquitto_pub -d -h localhost -t test -m "new hello" -p 8883 --cert client.crt --key client.key --capath /etc/ssl/certs/`
`mosquitto_pub -d -h serverIP -p 8883 -t test -m "new hello" --cert client.crt --key client.key --cafile /etc/ssl/certs/ca.crt --tls-version tlsv1.2`
 
Autenticação usando certificado, usuário e senha:
`mosquitto_sub --cafile /path/to/rootCA.pem -h <brokerhost> -p <brokerport> -m <message> -t <topic> -u "username" -P "password"`

> Terms Used
> CA = Certificate Authority
> Private Key = An encryption key that isn't shared and needs to be stored securely
> Public Key = An encryption key that is shared and doesn't needs to be stored securely.
> Certificate Request = An application for a certificate made to a certificate authority.