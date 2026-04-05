# Fail2ban Monitor — Intégration Home Assistant

Monitor votre serveur **Fail2ban** à distance via SSH, directement depuis Home Assistant.

---

## 🚀 Installation

### 1. Copier l'intégration

Copiez le dossier `fail2ban_monitor/` dans le répertoire des intégrations personnalisées de Home Assistant :

```
/config/custom_components/fail2ban_monitor/
```

La structure doit être :
```
custom_components/
└── fail2ban_monitor/
    ├── __init__.py
    ├── binary_sensor.py
    ├── config_flow.py
    ├── const.py
    ├── coordinator.py
    ├── manifest.json
    ├── sensor.py
    ├── ssh_client.py
    ├── strings.json
    └── translations/
        ├── en.json
        └── fr.json
```

### 2. Installer la dépendance Python

L'intégration utilise **paramiko** pour la connexion SSH.  
Home Assistant l'installe automatiquement au démarrage grâce au `manifest.json`.

Si vous avez un problème, installez-la manuellement :
```bash
pip install paramiko==3.4.0
```

### 3. Redémarrer Home Assistant

Après la copie, redémarrez Home Assistant pour charger l'intégration.

---

## ⚙️ Configuration

1. Allez dans **Paramètres → Appareils & Services → Ajouter une intégration**
2. Recherchez **"Fail2ban Monitor"**
3. Renseignez les paramètres :

| Champ | Description | Défaut |
|---|---|---|
| Adresse IP | IP ou hostname du serveur reverse proxy | — |
| Port SSH | Port SSH du serveur | `22` |
| Nom d'utilisateur | Login SSH | — |
| Mot de passe | Mot de passe SSH | — |
| Intervalle (s) | Fréquence de mise à jour | `60` |
| Utiliser sudo | Exécuter fail2ban-client avec sudo | `true` |

---

## 🔐 Pré-requis côté serveur

### Accès sudo sans mot de passe interactif (recommandé)

Pour éviter de stocker le mot de passe en clair dans les commandes sudo, configurez un accès `NOPASSWD` pour fail2ban-client :

```bash
# Sur le serveur reverse proxy
sudo visudo -f /etc/sudoers.d/fail2ban-ha
```

Ajoutez (remplacez `votre_user` par votre login SSH) :
```
votre_user ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client
```

Puis dans l'intégration, décochez "Utiliser sudo" — l'utilisateur aura déjà les droits.

### Vérifier que fail2ban-client est accessible

```bash
fail2ban-client ping
# Réponse attendue : Server replied: pong
fail2ban-client status
# Affiche la liste des jails
```

---

## 📊 Entités créées

### Binary Sensor
| Entité | Description |
|---|---|
| `binary_sensor.fail2ban_daemon_actif` | Le daemon fail2ban est-il en cours d'exécution ? |

### Sensors globaux
| Entité | Description |
|---|---|
| `sensor.fail2ban_nombre_de_jails` | Nombre total de jails configurés |
| `sensor.fail2ban_total_ip_bannies` | Nombre d'IP actuellement bannies (tous jails) |
| `sensor.fail2ban_total_tentatives_echouees` | Tentatives de connexion échouées en cours (tous jails) |

### Sensors par jail (créés dynamiquement)
Pour chaque jail découvert (ex: `sshd`, `nginx-http-auth`...) :

| Entité | Description |
|---|---|
| `sensor.fail2ban_<jail>_tentatives_actuelles` | Tentatives en cours (filtre) |
| `sensor.fail2ban_<jail>_total_tentatives` | Total des tentatives depuis démarrage |
| `sensor.fail2ban_<jail>_ip_bannies` | Nombre d'IP actuellement bannies |
| `sensor.fail2ban_<jail>_total_bans` | Total des bans depuis démarrage |
| `sensor.fail2ban_<jail>_fichiers_surveilles` | Nombre de fichiers de log surveillés |
| `sensor.fail2ban_<jail>_liste_ips_bannies` | Compteur + liste des IPs bannies en attributs |

### Attributs enrichis

Chaque capteur per-jail expose des **attributs** détaillés :
- **Liste IPs bannies** → attribut `banned_ips: [1.2.3.4, 5.6.7.8]`
- **Fichiers surveillés** → attribut `files: [/var/log/nginx/access.log]`
- **Total IP bannies (global)** → attribut `all_banned_ips: [...]`
- **Nombre de jails** → attribut `jails: [sshd, nginx-http-auth]`

---

## 💡 Exemples d'automatisations

### Notification quand une IP est bannie

```yaml
automation:
  - alias: "Alerte ban Fail2ban"
    trigger:
      - platform: state
        entity_id: sensor.fail2ban_total_ip_bannies
    condition:
      - condition: template
        value_template: >
          {{ trigger.to_state.state | int > trigger.from_state.state | int }}
    action:
      - service: notify.mobile_app
        data:
          title: "🚨 Fail2ban"
          message: >
            Nouvelle IP bannie !
            Total actuel : {{ states('sensor.fail2ban_total_ip_bannies') }} IP
```

### Alerte si le daemon s'arrête

```yaml
automation:
  - alias: "Fail2ban daemon arrêté"
    trigger:
      - platform: state
        entity_id: binary_sensor.fail2ban_daemon_actif
        to: "off"
    action:
      - service: notify.mobile_app
        data:
          title: "⚠️ Fail2ban"
          message: "Le daemon Fail2ban est arrêté sur le reverse proxy !"
```

---

## 🐛 Dépannage

| Problème | Solution |
|---|---|
| `cannot_connect` | Vérifiez l'IP, le port SSH et le firewall |
| `invalid_auth` | Vérifiez login/mot de passe |
| `fail2ban_not_found` | `fail2ban-client` absent ou pas dans le PATH |
| Les jails n'apparaissent pas | Fail2ban tourne ? (`fail2ban-client ping`) |
| Erreur sudo | Configurez `NOPASSWD` ou décochez "sudo" |

Consultez les logs Home Assistant :  
**Paramètres → Système → Journaux** et filtrez sur `fail2ban_monitor`.
