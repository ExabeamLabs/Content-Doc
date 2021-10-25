#### Parser Content
```Java
{
Name = wazuh-ssh-failed-login
  Product = Unix
  DataType = "authentication-failed"
  Conditions = [ """"decoder.parent":"sshd"""", "Failed", " for ", " from ", """"type":"wazuh-alerts"""" ]
  Fields = ${WazuhParserTemplates.wazuh-ssh-login.Fields} [
    """sshd\[.+?Failed.+?for (({domain}[^\\:]{1,2000})\\+)?({user}[\w.'\-\\$]{1,2000})"""
  ]
  DupFields = [ "description->failure_reason" ]
}
```