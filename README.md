# TP5 sécu : Man in the middle attack (MITM)

Dans ce TP on va créer un programme Python utilisant la librairie `scapy` pour intercepter les paquets d'un réseau et les modifier.

## Ce projet est à but éducatif, tout utilisation de ce code à des fins malveillantes est interdite.

# I. Installation

Commencez d'abord par installer les dépendances nécessaires au projet :

```bash
apt update
apt install python3 python3-pip
pip3 install scapy
```

Les commandes peuvent être différentes selon votre OS.
L'objectif est d'installer Python 3 et la librairie `scapy`.

Vous allez ensuite devoir cloner ce répertoire git sur votre machine :

```
git clone https://github.com/Aucorre/MITM.git
```

Pour la suite vous aurez besoin des droits d'administrateur sur votre machine.

# II. Utilisation

## 1. Man in the middle

Pour lancer l'attaque MITM, il suffit de lancer le fichier `Mitm.py` :

```bash
sudo python3 Mitm.py
```

Vous aurez ensuite à remplir 3 champs :

```
[*] Enter Desired Interface: {Interface}
[*] Enter Victim IP: {Victim ip}
[*] Enter Gateway IP: {Gatewayp ips}
```

Une option est disponible si vous rentrez à la place de l'IP de la victime `network`, l'attaque sera alors lancée sur tout le réseau.

```
[*] Enter Victim IP: network
```

Si l'attaque échoue, un message d'erreur s'affichera sur votre console expliquant pourquoi.

Vous pouvez aussi interrompre l'attaque en appuyant sur `Ctrl + C`.

## 2. DNS Spoofing

Une fois que l'attaque MITM est lancée, vous pouvez lancer le DNS Spoofing en lançant le fichier `DnsSpoof.py` :

```bash
sudo python3 DnsSpoof.py
```

Vous devrez ensuite rentrer l'interface utilisée par l'attaque MITM :

```
[*] Enter Desired Interface: {Interface}
```

Sur cette console, vous pouvez voir les requêtes DNS envoyées par les victimes.

Vous pouvez ensuite choisir de rediriger une requête DNS vers une autre adresse IP :

```
[*] Enter Victim Domain: {Victim domain}
[*] Enter Desired IP: {Desired ip}
```
