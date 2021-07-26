#### Parser Content
```Java
{
Name = wazuh-4624
  DataType = "windows-4624"
  Conditions = [ """"data.id":"4624"""", """"type":"wazuh-alerts"""", """"decoder.parent":"windows""""  ]
    Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """Type d\\u2019ouverture de session\\u00A0:\s{0,100}({logon_type}\d{1,100})"""
    """Nouvelle ouverture de session.*?Nom du compte\\u00A0:\s{0,100}({user}[^\s]{1,2000})\s{0,100}Domaine du compte\\u00A0:\s{0,100}({domain}[^\s]{1,2000})\s{0,100}ID d\\u2019ouverture de session\\u00A0:"""
    """Nom du processus\\u00A0:\s{0,100}(?:-|({process}[\w:\\.\-]{1,2000}))"""
    """Nom de la station de travail\\u00A0:\s{0,100}(-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host_windows}[^\s]{1,2000}))\s{0,100}Adresse du r\\u00E9seau source\\u00A0:"""
    """Adresse du r\\u00E9seau source\\u00A0:\s{0,100}(?:-|({src_ip}[\w:.]{1,2000}))\s{0,100}Port source\\u00A0:"""
    """Processus d\\u2019ouverture de session\\u00A0:\s{0,100}({auth_process}[^\s]{1,2000})\s{0,100}Package d\\u2019authentification\\u00A0:\s{0,100}({auth_package}[^\s]{1,2000})"""
    """ID d\\u2019ouverture de session\\u00A0:\s{0,100}({logon_id}[^\s]{1,2000})\s{0,100}GUID d\\u2019ouverture de session\\u00A0:"""
    """Nouvelle ouverture de session\\u00A0:\s{0,100}ID de s\\u00E9curit\\u00E9\\u00A0:\s{0,100}({user_sid}[^\s]{1,2000})\s"""
    ]
}
wazuh-windows-template = {
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"data.id":"({event_code}\d{1,100})""""
      """"@timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
      """"data.dstuser":"(\(no user\)|({dest_user}[^"]{1,2000}))"""
      """"data.status":"({outcome}[^"]{1,2000})"""
      """"location":"({log_location}[^"]{1,2000})"""
      """"data.data":"({data}[^"]{1,2000})"""
      """"path":"({log_path}[^"]{1,2000})"""
      """"data.system_name":"({host}[^"]{1,2000})"""
      """"agent.id":"({agent_id}\d{1,100})"""
      """"manager.name":"({wazuh_manager}[^"]{1,2000})"""
      """"data.data":"({data}[^"]{1,2000})"""
      """"rule.description":"({description}[^"]{1,2000})"""
      """"decoder.name":"({decoder_name}[^"]{1,2000})"""
    ]

```