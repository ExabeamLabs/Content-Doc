#### Parser Content
```Java
{
Name = wazuh-sys-auth-fail
  Product = Unix
  Vendor = Unix
  DataType = "authentication-failed"
  Conditions = [ """"type":"wazuh-alerts"""", """"rule.description":"syslog: User authentication failure."""" ]
  Fields = ${WazuhParserTemplates.wazuh-common-fields.Fields} [
    """"predecoder.hostname":"({host}[^"]{1,2000})""",
    """login failures for user ({user}[^\s]{1,2000})"""
]
  DupFields=["host->dest_host", "description->event_name"]
}
}
```