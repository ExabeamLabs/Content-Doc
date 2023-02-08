#### Parser Content
```Java
{
Name = symantec-security-alert-french
    Vendor = Symantec
    Product = Symantec Endpoint Protection
    Lms = Direct
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """SymantecServer""", """Source : Analyse""", """détecté""", """Action secondaire :""", """Jeu de catégories : Malware""" ]
    Fields = [
    """événement\s:\s({time}\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2})"""
    """SymantecServer:\s({event_name}[^,]{1,2000}),Adresse IP :"""
    """Adresse IP\s:\s({src_ip}[A-Fa-f\d:.]{1,2000})"""
    """Nom du risque\s:\s({alert_name}[^,]{1,2000})"""
    """Chemin de fichier :\s({process}(({directory}\w{1,2000}:[^,]{1,2000})[\\]{1,2000})?({process_name}[^\\.]{1,2000}\.[^\"\\,:]{1,2000}))"""
    """Action réelle\s:\s({action}[^,]{1,2000})"""
    """Nom du serveur\s:\s({host}[\w\-.]{1,2000})"""
    """Nom d’utilisateur\s:\s({user}[^,]{1,2000})"""
    """Hachage d’application :\s({md5}[^,]{1,2000})"""
    """Jeu de catégories :\s({alert_type}[^,]{1,2000})"""
    """Type de catégorie :\s({additional_info}[^,]{1,2000})"""
   ]	


}
```