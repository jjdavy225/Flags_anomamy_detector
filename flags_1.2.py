import tqdm
import pandas as pd
import argparse
import os.path
import sys

from functions import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Détection d'utilisateurs malveillants dans un réseau.")
    parser.add_argument("-d", "--csv_file", help="Chemin vers le fichier CSV des flux réseaus", required=True)
    parser.add_argument("--udp", action='store_true', help="Argument pour inclure les paquets UDP dans l'analyse")
    parser.add_argument("-t", "--deltaT", type=int, help="Valeur entière pour la durée d'une fenetre de calcul", default=25)
    parser.add_argument("-o", "--output", help="Fichier de sortie des calculs", default="x")


    args = parser.parse_args()
    
    if not os.path.exists(args.csv_file):
        print(f"Erreur : Le fichier CSV '{args.csv_file}' n'existe pas.")
        sys.exit(1)
    
    if args.deltaT <0:
        print("Erreur : La valeur de l'argument -t doit être positive.")
        sys.exit(1)
    
    if args.udp:
        udp = True
        print(f"Inclusion des paquets UDP, le programme pourrait prendre plus de temps...")
    else:
        udp = False
    
    print_separator()
    print("|{:^62}|{:^12}|".format("Tâches", "Statut"))
    print_separator()
    
    df = pd.read_csv(args.csv_file,delimiter=',')
    
    if not udp:
        df = df.query("Proto == 'tcp'")
    
    nb_agregation_par_fenetre = 5
    t_fenetre = args.deltaT
    print_table_row("Chargement du fichier fourni", "OK")
    
    dt =  int(t_fenetre/nb_agregation_par_fenetre)
    column_Label= False
    df['StartTime'] = pd.to_datetime(df['StartTime'])
    df['EndTime'] = df['StartTime'] + pd.to_timedelta(df['Dur'], unit='s')
    print_table_row("Prétraitement des données", "OK")
	
    if "Label" in df.columns :
        column_Label = True
        df["target"] = df['Label'].str.contains("Botnet").astype(int)
        
        targets_srcIP =  df.groupby("SrcAddr")["target"].unique()
        targets_srcIP = {ip:val[0] for  ip,val in targets_srcIP.items()}
        predictions_majeur_srcIP = {ip:0 for  ip in targets_srcIP.keys()}
        predictions_mineur_srcIP = {ip:0 for  ip in targets_srcIP.keys()}
        
        targets_dstIP =  df.groupby("DstAddr")["target"].unique()
        targets_dstIP = {ip:val[0] for  ip,val in targets_dstIP.items()}
        predictions_majeur_dstIP = {ip:0 for  ip in targets_dstIP.keys()}
        predictions_mineur_dstIP = {ip:0 for  ip in targets_dstIP.keys()}
    else:
        predictions_srcIP = {ip:0 for ip in df["SrcAddr"].unique()}
        
        predictions_dstIP = {ip:0 for ip in df["DstAddr"].unique()}
    

    ## découpage des flux en morceaux de 5min par fenetre de calcul
    fenetre_donnees = segmentation_of_dataFrame(df,dt)   
    print_table_row("Découpage par fenêtre de temps de calcul", "OK")

    if len(fenetre_donnees)<nb_agregation_par_fenetre:
       print("Le temps total d'enregistrement de vos données est insuffisant.\nVous avez deux solutions:\n\t"+
			 "1- Fournir un enregistrement d'au moins 25 minutes.\n\t2- Configurer le programme pour travailler sur une fenêtre de temps réduite "+
			 "(utilisez l'option -t n si votre enregistrement dure au moins n minutes).")

    else:
        print_table_row(f"Il y a {len(fenetre_donnees)-nb_agregation_par_fenetre+1} fenetre(s) de temps de calcul de {t_fenetre}min chacune", "")
        oldResult = {'srcIP' : {}, 'dstIP' : {}}

        print_table_row("Début de la prédiction", "En cours")
        print_separator()
        
        for t in tqdm.tqdm(range(nb_agregation_par_fenetre,len(fenetre_donnees)+1)):
            data_matrice_src,liste_ip_src = matrice_des_entropie(fenetre_donnees,t,oldResult, nb_agregation_par_fenetre, mode="srcIP")
            data_matrice_dst,liste_ip_dst = matrice_des_entropie(fenetre_donnees,t,oldResult, nb_agregation_par_fenetre, mode="dstIP")
            
            seuil_anomalie_majeur_src = 2
            seuil_anomalie_mineur_src = 415
            seuil_anomalie_majeur_dst = 0.5
            seuil_anomalie_mineur_dst = 200
            
            les_bots_majeur_src,les_bots_mineur_src = predire(data_matrice_src,liste_ip_src,seuil_anomalie_majeur_src,seuil_anomalie_mineur_src)
            les_bots_majeur_dst,les_bots_mineur_dst = predire(data_matrice_dst,liste_ip_dst,seuil_anomalie_majeur_dst,seuil_anomalie_mineur_dst)
            for ip in les_bots_majeur_src:
                predictions_majeur_srcIP[ip] = 1
            for ip in les_bots_mineur_src:
                predictions_mineur_srcIP[ip] = 1
            for ip in les_bots_majeur_dst:
                predictions_majeur_dstIP[ip] = 1
            for ip in les_bots_mineur_dst:
                predictions_mineur_dstIP[ip] = 1
        print_separator()
        print_table_row("Prédictions","OK")
        # On affiche les scores de notre algorithme ou on enregistre les prédictions en fonction de la présence de la colonne "Label" dans nos données.
        
        #Calcul des metriques
            
        print_table_row("Calcul des scores", "OK")
        print_separator()
        
        print("---------------[\tLes scores pour le modèle des IP sources\t\t]---------------")
        print("\t\t\tLes majeurs")
        calcul_metrique(predictions_majeur_srcIP, targets_srcIP)
        print("\n\t\t\tLes mineurs")
        calcul_metrique(predictions_mineur_srcIP, targets_srcIP)
        print("\n---------------[\tLes scores pour le modèle des IP destinations\t\t]---------------")
        print("\t\t\tLes majeurs")
        calcul_metrique(predictions_majeur_dstIP, targets_dstIP)
        print("\n\t\t\tLes mineurs")
        calcul_metrique(predictions_mineur_dstIP, targets_dstIP)
            
        # enregistrement des résultats dans un fichier
        if args.output !='x':
            df['predict_sIP_majeur'] = df['SrcAddr'].map(lambda name: map_value(predictions_majeur_srcIP.get(name)))
            df['predict_sIP_mineur'] = df['SrcAddr'].map(lambda name: map_value(predictions_mineur_srcIP.get(name)))
            df['predict_dIP_majeur'] = df['DstAddr'].map(lambda name: map_value(predictions_majeur_dstIP.get(name)))
            df['predict_dIP_mineur'] = df['DstAddr'].map(lambda name: map_value(predictions_mineur_dstIP.get(name)))
            output_file = args.output
            df.to_csv(output_file, index=False)
            print("Les prédictions ont été ajoutées aux données, dans une nouvelle colonne 'predict' et le tout enregisté dans {output_file}.")

