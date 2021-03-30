#### Parser Content
```Java
{
Name = wazuh-4624
  DataType = "windows-4624"
  Conditions = [ """"data.id":"4624"""", """"type":"wazuh-alerts"""", """"decoder.parent":"windows""""  ]
    Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """Type d\\u2019ouverture de session\\u00A0:\s*({logon_type}\d+)"""
    """Nouvelle ouverture de session.*?Nom du compte\\u00A0:\s*({user}[^\s]+)\s*Domaine du compte\\u00A0:\s*({domain}[^\s]+)\s*ID d\\u2019ouverture de session\\u00A0:"""
    """Nom du processus\\u00A0:\s*(?:-|({process}[\w:\\.\-]+))"""
    """Nom de la station de travail\\u00A0:\s*(-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host_windows}[^\s]+))\s*Adresse du r\\u00E9seau source\\u00A0:"""
    """Adresse du r\\u00E9seau source\\u00A0:\s*(?:-|({src_ip}[\w:.]+))\s*Port source\\u00A0:"""
    """Processus d\\u2019ouverture de session\\u00A0:\s*({auth_process}[^\s]+)\s*Package d\\u2019authentification\\u00A0:\s*({auth_package}[^\s]+)"""
    """ID d\\u2019ouverture de session\\u00A0:\s*({logon_id}[^\s]+)\s*GUID d\\u2019ouverture de session\\u00A0:"""
    """Nouvelle ouverture de session\\u00A0:\s*ID de s\\u00E9curit\\u00E9\\u00A0:\s*({user_sid}[^\s]+)\s"""
    ]
}
wazuh-windows-template = {
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"data.id":"({event_code}\d+)""""
      """"@timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
      """"data.dstuser":"(\(no user\)|({dest_user}[^"]+))"""
      """"data.status":"({outcome}[^"]+)"""
      """"location":"({log_location}[^"]+)"""
      """"data.data":"({data}[^"]+)"""
      """"path":"({log_path}[^"]+)"""
      """"data.system_name":"({host}[^"]+)"""
      """"agent.id":"({agent_id}\d+)"""
      """"manager.name":"({wazuh_manager}[^"]+)"""
      """"data.data":"({data}[^"]+)"""
      """"rule.description":"({description}[^"]+)"""
      """"decoder.name":"({decoder_name}[^"]+)"""
    ]

```