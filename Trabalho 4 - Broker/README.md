# Trabalho 4 - Broker MQTT

O protocolo **MQTT** define dois tipos de entidades na rede: um message **broker** e inúmeros **clientes**.

O **broker** é um servidor que recebe todas as mensagens dos clientes e, em seguida, roteia essas mensagens para os **clientes** de destino relevantes.

Por sua vez, um **cliente** é qualquer coisa que possa interagir com o **broker** e receber mensagens. Um **cliente** pode ser um sensor de **IoE** em campo ou um aplicativo em um data center que processa dados de **IoE**. O **cliente** conecta-se, por meio de uma conexão **TCP/IP** simples ou uma conexão **TLS encriptada** (para mensagens sensíveis), ao **broker** e pode assinar qualquer **"tópico"** de mensagem no **broker**.

O **cliente** publica as mensagens em um tópico, enviando a mensagem e o tópico ao **broker**. Em seguida, o **broker** encaminha a mensagem a todos os **clientes** que assinam esse tópico.

Como as mensagens do **MQTT** são organizadas por tópicos, o desenvolvedor tem a flexibilidade de especificar que determinados **clientes** somente podem interagir com determinadas mensagens. Por exemplo, os sensores publicarão suas leituras no tópico **"sensor_data"** e assinarão o tópico **"config_change"**.

Os aplicativos de processamento de dados que salvam os dados do sensor em um banco de dados de backend assinarão o tópico **"sensor_data"**. Um aplicativo de console administrativo poderia receber comandos do administrador do sistema para ajustar as configurações dos sensores, como a sensibilidade e a frequência de amostragem, e publicar essas mudanças no tópico **"config_change"**.

**Atividade avaliativa** (em dupla): O **Mosquitto** é um **broker** (intermediário) de mensagens **MQTT**, desenvolvido em código aberto pela Eclipse Foundation.

Elaborar o vídeo em formato MP4 com os procedimentos para disponibilização do serviço MQTT localmente (preferencialmente em Linux), por meio da instalação do broker Mosquitto.

Como instalar o broker do Mosquitto e o cliente Mosquitto MQTT no Linux Debian:

- Atualização dos pacotes: `sudo apt-get update`
- Instalar o serviço **Mosquitto Broker** que utilizará a porta **1883/TCP**: `sudo apt-get install mosquitto`
- Instalar o **cliente Mosquitto**: `sudo apt-get install mosquitto-clients`

**Obs**: Se ocorrer algum erro no processo de instalação relacionado a disponibilidade desses pacotes no repositório da distribuição Linux, tente executar o comando: 

`sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa`

E então repetir as instalações.

Para verificar se o serviço **Mosquitto** está em execução, utiliza-se o comando:

`netstat -na |grep 1883`

Os seguintes comandos permitem parar e, em sequência iniciar o **broker mosquitto**:

```
sudo service mosquitto stop
sudo service mosquitto start
```

Nas distribuições Linux, existem dois principais métodos adotados oficialmente para controlar serviços (com auxílio do **sudo**). Por exemplo para o serviço **HTTP**:

**systemctl**

Exemplos:

`sudo systemctl stop httpd`
`sudo systemctl start httpd`
     
**service**

Exemplos:

`sudo service httpd start`
`sudo service httpd stop`