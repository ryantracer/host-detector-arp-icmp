# detector-de-hosts-arp-icmp
Um pequeno script de python que criei para praticar enquanto faço alguns estudos, projeto feito com fins educativos.

# Como funciona
O script usa a biblioteca netifaces para conseguir o endereço de IP do usuário dentro da interface de rede selecionada, convertendo a máscara de rede para o formato necessário para a notação CIDR (ex.: 255.255.255.0 => 24) (função get_local). A interface de rede deve ser fornecida pelo usuário.

Através do resultado, a função net_scanner utilizará solicitações ARP para obter o IP e endereço MAC das máquinas que responderem, esse teste normalmente resultará na maior quantidade de respostas. Para obter um pouco mais, o programa enviará solicitações ICMP, normalmente trazendo menos resultados pois essas podem ser mais fácilmente bloqueadas, os resultados serão salvos em um host.txt criado automáticamente (o arquivo só será criado após o fim do processo, quando o usuário pressionar CTRL-C ou todos os IPs forem escaneados).

É um projeto simples de estudos e feito para testes e aprender a lidar com redes, o código pode estar bagunçado e precisar ser refatorado futuramente.
