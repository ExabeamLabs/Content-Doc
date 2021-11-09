#### Parser Content
```Java
{
Name = wazuh-pam-auth-fail
  Product = Unix
  Vendor = Unix
  DataType = "authentication-failed"
  Conditions = [ """"type":"wazuh-alerts"""", """"rule.description":"PAM: User login failed."""" ]
  Fields = ${WazuhParserTemplates.wazuh-common-fields.Fields} [
    """"predecoder.hostname":"({host}[^"]{1,2000})""",
    """"data.dstuser":"({user}[^"]{1,2000})""",
    """"data.uid":"({user_uid}[^"]{1,2000})"""  
]
  DupFields=["host->dest_host", "description->event_name"]
}
}
```