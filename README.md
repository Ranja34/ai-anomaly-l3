# Conception et automatisation d’un réseau autonome avec l’IA

## 1. Présentation du projet

Ce projet de mémoire de Licence 3 porte sur la conception d’un système de supervision et de remédiation automatique des incidents système et réseau, avec une intégration progressive de l’intelligence artificielle pour la détection d’anomalies.

L’objectif est de détecter les incidents, de les diagnostiquer et d’automatiser certaines actions correctives dans un environnement de laboratoire contrôlé.

## 2. Architecture du laboratoire

Le prototype repose sur deux machines virtuelles Ubuntu :

- **Serveur de supervision :** Prometheus, Grafana et scripts Python.
- **Serveur cible :** Nginx, SSH et Node Exporter.

Prometheus collecte les métriques, Grafana les visualise et les règles d’alerte détectent certains états anormaux. Un contrôleur Python surveille les alertes et peut déclencher un playbook Ansible pour une action corrective autorisée.

## 3. Technologies utilisées

- Ubuntu Server / Ubuntu
- Prometheus
- Grafana
- Node Exporter
- Python
- scikit-learn
- Ansible
- Nginx
- Git

## 4. Fonctionnalités réalisées

- Collecte et visualisation des métriques système.
- Détection par règles de certains incidents CPU, mémoire, disque et disponibilité de services.
- Détection d’anomalies expérimentale avec Isolation Forest sur un jeu de données public.
- Remédiation automatique de l’indisponibilité de Nginx dans le laboratoire.
- Vérification de la cohérence des dépendances Python.

## 5. État actuel et limites

La chaîne de détection et de remédiation automatique a été testée avec succès pour l’arrêt de Nginx dans le laboratoire.

Les autres scénarios de remédiation ne sont pas encore tous implémentés ni validés. Le modèle Isolation Forest reste expérimental : ses performances sur un jeu de données public ne démontrent pas encore son efficacité sur les métriques propres à l’environnement cible.

Aucune mise en production ne doit être effectuée sans autorisation explicite et validation des actions correctives.

## 6. Installation des dépendances Python

Dans un environnement Python compatible, créer et activer un environnement virtuel, puis exécuter :

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Les services Prometheus, Grafana, Node Exporter, SSH et Ansible nécessitent une configuration complémentaire selon l’environnement.

## 7. Structure du dépôt

- `src/` : scripts de détection et de remédiation.
- `ansible/` : playbooks et modèles de configuration.
- `data/` : données d’apprentissage et de test, non publiées par défaut.
- `models/` : modèles entraînés, non publiés par défaut.
- `reports/` : rapports d’évaluation.
- `train_isolation_forest.py` : script d’entraînement.
- `requirements.txt` : dépendances Python.

## 8. Évolutions prévues

- Améliorer la robustesse du contrôleur de remédiation.
- Implémenter et valider d’autres scénarios d’incidents.
- Évaluer l’IA sur des métriques compatibles avec la supervision réelle.
- Ajouter des tests, des journaux d’audit et des mécanismes de validation après correction.
- Documenter les limites, les faux positifs et les conditions d’autorisation des actions automatiques.

## 9. Contexte académique

Projet réalisé dans le cadre d’un mémoire de Licence 3. Le prototype est développé et testé dans un laboratoire isolé ; toute adaptation à une infrastructure professionnelle dépend des autorisations, des exigences de sécurité et des validations de l’organisation concernée.
