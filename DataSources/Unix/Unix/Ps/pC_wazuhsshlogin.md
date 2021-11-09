#### Parser Content
```Java
{
Name = wazuh-ssh-login
  Product = Unix
  Conditions = [ """"decoder.parent":"sshd"""", "Accepted ", " for ", " from ", """"type":"wazuh-alerts"""" ]
  Fields = ${WazuhParserTemplates.wazuh-ssh-login.Fields} [
    """sshd\[.+?Accepted ({auth}\S+) for (({domain}[^\\:]{1,2000})\\+)?({user}[\w.'\-\\$]{1,2000})"""
  ]
}
}
```