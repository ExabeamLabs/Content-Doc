#### Parser Content
```Java
{
Name = wazuh-4625
  DataType = "windows-failed-logon"
  Conditions = [ """"data.id":"4625"""", """"type":"wazuh-alerts"""", """"decoder.parent":"windows""""  ]
    Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """Type d\\u2019ouverture de session\\u00A0:\s*({logon_type}\d+)"""
    """Nom de la station de travail\\u00A0:\s*(-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host_windows}[^\s]+))\s*Adresse du r\\u00E9seau source\\u00A0:"""
    """Nom de la station de travail\\u00A0:\s*(-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[^\s]+))\s*Adresse du r\\u00E9seau source\\u00A0:\s*-\s+"""
    """Adresse du r\\u00E9seau source\\u00A0:\s*(?:-|({src_ip}[\w:.]+))\s*Port source\\u00A0:"""
    """Processus d\\u2019ouverture de session\\u00A0:\s*({auth_process}[^\s]+)\s*Package d\\u2019authentification\\u00A0:\s*({auth_package}[^\s]+)"""
    """\s*Compte pour lequel l\\u2019ouverture de session a \\u00E9chou\\u00E9\\u00A0:\s*ID de s\\u00E9curit\\u00E9\\u00A0:\s*(?:\/?NULL SID|({user_sid}.+?))\s*Nom du compte\\u00A0"""
    """ouverture de session a \\u00E9chou\\u00E9\\u00A0:.+?Domaine du compte\\u00A0:\s*(?=\w)({domain}.+?)\s*Informations sur l\\u2019\\u00E9chec\\u00A0"""
    """ouverture de session a \\u00E9chou\\u00E9\\u00A0:.+?Nom du compte\\u00A0:\s*(?=\w)({user}.+?)\s*Domaine du compte\\u00A0:"""
    """Raison de l\\u2019\\u00E9chec\\u00A0:\s*({failure_reason}.+?)\s*\\u00C9tat\\u00A0:"""
    """Sujet.+?Nom du compte\\u00A0:\s*(?=\w)({caller_user}.+?)\s*Domaine du compte\\u00A0:"""
    """Sujet.+?Domaine du compte\\u00A0:\s*(?=\w)({caller_domain}[^:]+?)\\s*ID d\\u2019ouverture de session\\u00A0:"""
    """\s*Sous-\\u00E9tat\\u00A0:\s*({result_code}.+?)\s*Informations sur le processus\\u00A0:"""
    ]
}
```