#### Parser Content
```Java
{
Name = wazuh-ping-app-login-2
  Conditions = [ """"data.type":"SSO"""", """"type":"wazuh-alerts"""" ]
  Fields = ${WazuhParserTemplates.wazuh-ping-app-template.Fields} [
    """({event_code}SSO)"""
  ]
}
}
```