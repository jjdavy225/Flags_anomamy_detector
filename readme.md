Flags est un algorithme de détection d'anomalie basé sur l'entropie. Vous trouvez ici notre implémentation de cet algorithme.
Pour le tester, il vous faut une capture netflow.
Réaliser les étapes suivantes après avoir cloné le repo :

# Install librairies first:
    pip install -r requirements.txt


# Start program:
    python flags.py -d netflows.csv


# Help:
    python flags.py -h
