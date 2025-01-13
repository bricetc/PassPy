# Système de gestion et d'analyse de mot de passe
--------------------------------------


Groupe: 
    I, P, K, Joseph

Objectifs: 
    - Analyser la force de mots de passe
    - Générer des mots de passe robustes
    - Stocker les mots de passes de manière sécurisée
    - Simuler des attaques de brutes force et de dictionnaire
    - Appliquer les techniques NLP 

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/password_app.git
cd password_app


Phase 1: Recherche et préparation de données
------
    Dans cette phase, nous collectons des bases de données de mdp 
    et préparons pour l'entrainement
    - Nous constituons notre base de données de mdp à partir des fichiers
    obtenus de Seclists
        db : passdb.txt
    - Nous nettoyons ensuite la base de données retirant doublons et normalisation
        db : cleaned_passdb.csv
    - Nous séparons les mots de passe en differentes categories (weak, medium, strong)
        db : categ_passdb.csv


Phase 2: Analyse de la force des mots de passe
------- 
    Nous construisons donc un modèle de machine learning capable de prédire
    la foce d'un mot de passe
    - Définition les caractérisques d'un mot de passe
        length | uppercase | lowercase | digits | special_chars | sequential | entropy
    
    - Nous entrainons donc un modèle supervisé avec la technique RandomForest 
        model : 

    - Nous testons la précision du modèle


Phase 3: Génération de mots de passe sécurisée
-------
    Implémentation d'un algo pour générer des mots de passe robustes, sans pattern faciles 
    à déviner
    - Nous développons un générateur de mot de passe aléatoires 

    - Intégration d'une logique pour exclure les patterns faciles

    - Utilisation des Techniques NLP pour filtrer les mots de passe basés sur ceux communs


Phase 4: Stockage Sécurisé des Mots de Passe 
--------    
    Implémentation d'un gestionnaire de mot de passe avec chiffrement fort
    - Nous créons une base de données stocker les mots de passe (avec AES)

    - Implémentons des fonctions de chiffrement/déchiffrement 

    - Utilisons bcrypt pour le hachage sécurisé des mots de passe


Phase 5: Simulation d'attaques brute-force et dictionnaire
--------
    Test de la résistance des mots de passe générés
    - Nous implémentons un moteur d'attaques brute-force 

    - Nous implémentons un moteur d'attaques 

    - Mesure de temps, ressources nécessaires pour casser

Phase 6: Tests et Validation
--------
    Test de l'ensemble du système sur différents mots de passe et évaluation 
    des perfs
    - Vérification la précision de l'analyse de la force des mdp
    - Validation de la robustesse des mdp
    - Chiffriment et dechiffrement bien implémenté
    - Simuler les attaques pour tester la robustesse




