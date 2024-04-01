from collections import Counter
import numpy as np
from sklearn.decomposition import PCA
import pandas as pd

def fenetre_temporelle(df, duree, date_start_window):
	"""
	Sélectionne les données dans une fenêtre temporelle spécifiée.

	Arguments :
	df : DataFrame - Le DataFrame contenant les données.
	duree : int - Durée de la fenêtre temporelle en minutes.
	date_start_window : Timestamp - Date de début de la fenêtre temporelle.

	Retourne :
	fenetre_data : DataFrame - Les données dans la fenêtre temporelle spécifiée.
	"""
	# Déterminer la date de fin de la fenêtre temporelle
	date_end_window = date_start_window + pd.Timedelta(minutes=duree)

	# Sélectionner les données de la fenêtre temporelle
	fenetre_data = df[((df['StartTime'] < date_start_window) & (df['EndTime'] >= date_start_window)) |
					  ((df['StartTime'] <= date_end_window) & (df['StartTime'] >= date_start_window))]
	return fenetre_data

def segmentation_of_dataFrame(datas, window_time_size=5):
	"""
	Divise un DataFrame en segments de temps spécifiés.

	Arguments :
	datas : DataFrame - Le DataFrame contenant les données.
	window_time_size : int - Taille de la fenêtre temporelle en minutes.

	Retourne :
	fenetre_donnees : list - Une liste de DataFrames, chaque DataFrame représentant une fenêtre temporelle.
	"""
	fenetre_donnees = []

	date_start_window = datas['StartTime'].min()
	while (date_start_window < datas['StartTime'].max()):
		fenetre_donnees.append(fenetre_temporelle(datas, window_time_size, date_start_window))
		date_start_window += pd.Timedelta(minutes=window_time_size)
	return fenetre_donnees

def upload_data(df, mode):
	"""
	Prétraite les données en filtrant les adresses IP sources avec un compte supérieur à 1.

	Arguments :
	df : DataFrame - Le DataFrame contenant les données.
	mode : String - In ["srcIP" , "dstIP"] spécifiant le mode du modèle

	Retourne :
	format_data : defaultdict - Un dictionnaire contenant les données formatées.
	ip_flux_une_fois : list - Liste des adresses IP qui apparaissent une seule fois.
	"""
	# Compter le nombre d'occurrences de chaque adresse IP source / destination
	if mode == 'srcIP' :
		ip_mode_column = 'SrcAddr'
		format_key_ip_mode = 'liste_dest_IP'
	else:
		ip_mode_column = 'DstAddr'
		format_key_ip_mode = 'liste_src_IP'
  
	counts = df[ip_mode_column].value_counts()
	# Filtrer les adresses IP sources/destinations avec un compte supérieur à 1
	ips_a_garder = counts[counts >= 2].index.tolist()
	# Filtrer les données d'entrée pour ne conserver que celles dont l'adresse IP source est dans ips_a_garder
	df_filtre = df[df[ip_mode_column].isin(ips_a_garder)]
	# Récupérer les adresses IP qui apparaissent une seule fois
	ip_flux_une_fois = df.loc[~df[ip_mode_column].isin(ips_a_garder), ip_mode_column].unique()

	# Créer un dictionnaire pour stocker les données formatées
	format_data = {}
	for ip, group in df_filtre.groupby(ip_mode_column):
		format_data[ip] = {
			"liste_src_P": group['Sport'].tolist(),  # Convertir les colonnes en listes
			"liste_dest_P": group['Dport'].tolist(),
			format_key_ip_mode : group[ip_mode_column].tolist(),
			"liste_flags": group['State'].tolist()
		}

	return format_data, ip_flux_une_fois

def calcul_entropies(datas, ip_sources_entropie_zeros, mode):
	"""
	Calcule les entropies des données pour chaque adresse IP source.

	Arguments :
	datas : defaultdict - Un dictionnaire contenant les données formatées.
	ip_sources_entropie_zeros : list - Liste des adresses IP avec entropie nulle.
	mode : String - In ["srcIP" , "dstIP"] spécifiant le mode du modèle

	Retourne :
	entropries : dict - Un dictionnaire contenant les entropies calculées pour chaque adresse IP source.
	"""
	if mode == 'srcIP' :
		data_key_ip_mode = 'liste_dest_IP'
		H_IP_mode = 'H_dest_IP'
	else:
		data_key_ip_mode = 'liste_src_IP'
		H_IP_mode = 'H_src_IP'

	histogramme = {adresse_ip: {"liste_src_P": Counter(dic_list["liste_src_P"]), "liste_dest_P": Counter(dic_list["liste_dest_P"]),
								data_key_ip_mode: Counter(dic_list[data_key_ip_mode]),
								"liste_flags": Counter(dic_list["liste_flags"])}
				   for adresse_ip, dic_list in datas.items()}

	probabilites = {ip_source: {"liste_src_P": {port: count / sum(dic_listip_src["liste_src_P"].values()) for port, count in
												 dic_listip_src["liste_src_P"].items()},
								"liste_dest_P": {port: count / sum(dic_listip_src["liste_dest_P"].values()) for port,
												 count in dic_listip_src["liste_dest_P"].items()},
								data_key_ip_mode: {ip_dest: count / sum(dic_listip_src[data_key_ip_mode].values()) for
												  ip_dest, count in dic_listip_src[data_key_ip_mode].items()},
								"liste_flags": {flag: count / sum(dic_listip_src["liste_flags"].values()) for flag, count
												in dic_listip_src["liste_flags"].items()}}
					for ip_source, dic_listip_src in histogramme.items()}

	entropries = {adresse_ip: {"H_src_P": -sum([p * np.log2(p) for p in dic_listip_src["liste_src_P"].values()]),
							   "H_dest_P": -sum([p * np.log2(p) for p in dic_listip_src["liste_dest_P"].values()]),
							   H_IP_mode: -sum([p * np.log2(p) for p in dic_listip_src[data_key_ip_mode].values()]),
							   "H_flags": -sum([p * np.log2(p) for p in dic_listip_src["liste_flags"].values()])}
				  for adresse_ip, dic_listip_src in probabilites.items()}
	for ip in ip_sources_entropie_zeros:
		entropries[ip] = {"H_src_P": 0, "H_dest_P": 0, H_IP_mode: 0, "H_flags": 0}
	return entropries

def calcul_scores(k, data_matrix, significant_components, eigenvalues):
	"""
	Calcule les scores d'anomalie pour chaque observation.

	Arguments :
	k : int - Séparateur de la variance des composantes majeures et mineures.
	data_matrix : array - Matrice de données.
	significant_components : array - Composantes principales significatives.
	eigenvalues : array - Valeurs propres.

	Retourne :
	anomaly_scores_majeur : array - Scores d'anomalie pour les composantes majeures.
	anomaly_scores_mineur : array - Scores d'anomalie pour les composantes mineures.
	"""
	# Projetion des données originales sur les composantes principales significatives
	projected_data_majeur = data_matrix.dot(significant_components.T[:, :k])
	projected_data_mineur = data_matrix.dot(significant_components.T[:, k:])

	# Calcul des scores d'anomalie pour chaque observation
	# Division par les carrés des valeurs propres
	eigenvalues_squared_majeur = np.square(eigenvalues)[:k]
	eigenvalues_squared_mineur = np.square(eigenvalues)[k:]

	anomaly_scores_majeur = np.sum(np.square(projected_data_majeur) / eigenvalues_squared_majeur, axis=1)
	anomaly_scores_mineur = np.sum(np.square(projected_data_mineur) / eigenvalues_squared_mineur, axis=1)

	return anomaly_scores_majeur, anomaly_scores_mineur


def matrice_des_entropie(fenetre_donnees, fenetre_t, oldResult, nb_agregation_par_fenetre, mode):
	"""
	Calcule la matrice des entropies pour une fenêtre de données.

	Arguments :
	fenetre_donnees : list - Une liste de DataFrames, chaque DataFrame représentant une fenêtre temporelle.
	fenetre_t : int - Nombre de fenêtres de données.
	mode : String - In ["srcIP" , "dstIP"] spécifiant le mode du modèle

	Retourne :
	data_matrice : array - Matrice des entropies.
	liste_ip_sources : list - Liste des adresses IP sources.
	"""
	if mode == 'srcIP':
		H_IP_mode = 'H_dest_IP'
	else: 
		H_IP_mode = 'H_src_IP'

	data_matrix_dict = {}
	t = 0
	for i in range(fenetre_t - nb_agregation_par_fenetre, fenetre_t):
		if i not in oldResult[mode].keys():
			datas, ip_sources_entropie_zeros = upload_data(fenetre_donnees[i], mode)
			entropries = calcul_entropies(datas, ip_sources_entropie_zeros, mode)
			oldResult[mode][i] = entropries
		else: entropries = oldResult[mode][i]
  
		for ip in entropries.keys():
			if ip not in data_matrix_dict:
				data_matrix_dict[ip] = {"H_src_P": [0] * nb_agregation_par_fenetre, "H_dest_P": [0] * nb_agregation_par_fenetre, H_IP_mode: [0] * nb_agregation_par_fenetre,
										"H_flags": [0] * nb_agregation_par_fenetre}

			data_matrix_dict[ip]["H_src_P"][t] = entropries[ip]["H_src_P"]
			data_matrix_dict[ip]["H_dest_P"][t] = entropries[ip]["H_dest_P"]
			data_matrix_dict[ip][H_IP_mode][t] = entropries[ip][H_IP_mode]
			data_matrix_dict[ip]["H_flags"][t] = entropries[ip]["H_flags"]
		t += 1

	# Création de la matrice des entropies
	data_matrice = np.array([[entropies["H_src_P"] + entropies["H_dest_P"] + entropies[H_IP_mode] + entropies["H_flags"]]
							 for _, entropies in data_matrix_dict.items()])

	data_matrice = np.vstack(data_matrice)
	liste_ip_sources = list(data_matrix_dict.keys())
 
	

	return data_matrice, liste_ip_sources

def predire(data_matrice, ips_fenetre, seuil_anomalie_majeur, seuil_anomalie_mineur):
	
	# Création de l'objet PCA, possibilités de définir le nombre de composantes désiré en paramètres
	pca = PCA()

	# Adapter le PCA aux données
	pca.fit(data_matrice)

	# Obtenir les composantes principales et leurs valeurs propres
	principal_components = pca.components_
	eigenvalues = pca.explained_variance_

	# Sélectionner les composantes principales significatives, le seuil 1e-6 est choisi selon l'article.
	significant_components = principal_components[eigenvalues > 1e-6]
	eigenvalues = eigenvalues[:significant_components.shape[0]]

	# Calcul des scores
	k = 1  # Séparateur de la variance des composantes majeures et mineures
	anomaly_scores_majeur, anomaly_scores_mineur = calcul_scores(k, data_matrice, significant_components, eigenvalues)

	# Prédiction des anomalies
	predictions_majeur = anomaly_scores_majeur > seuil_anomalie_majeur
	predictions_mineur = anomaly_scores_mineur > seuil_anomalie_mineur
	les_bots_majeur = []
	les_bots_mineur = []

	labels = {ip: 0 for ip in ips_fenetre}
	for ip in range(len(predictions_majeur)):
		if predictions_majeur[ip]:
			key = ips_fenetre[ip]
			labels[key] = 1
			les_bots_majeur.append(key)
		if predictions_mineur[ip]:
			key = ips_fenetre[ip]
			labels[key] = 1
			les_bots_mineur.append(key)

	return les_bots_majeur,les_bots_mineur

def map_value(value):
    return "Botnet" if value == 1 else "Normal"

def print_table_row(title, status):
    print(f"| {title:<60} | {status:^10} |")

def print_separator():
    print("+{:-<62}+{:-^12}+".format("", ""))
    
def calcul_metrique(predictions,target):
	C_TP=0
	C_TN=0
	C_FP=0
	C_FN=0
	for ip,val in predictions.items():
		if target[ip]:
			if val:
				C_TP+=1
			else:
				C_FN+=1
			
		else:
			if val:
				C_FP+=1
			else:
				C_TN+=1

	print_separator()
	print_table_row("Count True Positive",C_TP)
	print_table_row("Count True Negative",C_TN)
	print_table_row("Count False Negative",C_FN)
	print_table_row("Count False Positive",C_FP)
	print_separator()

	try: FPR = (C_TP/(C_TN+C_FP))*100
	except ZeroDivisionError: FPR = 0

	try: TPR = (C_TP/(C_TP+C_FN))*100
	except ZeroDivisionError: TPR = 0

	try: TNR = (C_TN/(C_TN+C_FP))*100
	except ZeroDivisionError: TNR = 0

	try: FNR = (C_FN/(C_TP+C_FN))*100
	except ZeroDivisionError: FNR = 0

	try: precision = C_TP/(C_TP + C_FP)*100
	except ZeroDivisionError: precision = 0
 
	try: accuracy = ((C_TP + C_TN)/(C_TP+C_TN+C_FP+C_FN))*100
	except ZeroDivisionError: accuracy = 0
	try: errorRate = ((C_FN+C_FP)/(C_TP+C_TN+C_FP+C_FN))*100
	except ZeroDivisionError: errorRate = 0
	try: f_measure = (2*precision*TPR/(precision+TPR))*100 
	except (ZeroDivisionError,TypeError): f_measure = 0

	print_separator()
	print_table_row("TPR ",f"{TPR:.2f}")
	print_table_row("TNR ",f"{TNR:.2f}")
	print_table_row("FPR ",f"{FPR:.2f}")
	print_table_row("FNR ",f"{FNR:.2f}")
	print_table_row("precision ",f"{precision:.2f}")
	print_table_row("accuracy ",f"{accuracy:.2f}")
	print_table_row("error_rate ",f"{errorRate:.2f}")
	print_table_row("f_measure  ",f"{f_measure:.2f}")
	print_separator()