#### Parser Content
```Java
{
Name = wazuh-unix-sudo-su-2
  Product = Unix
  Vendor = Unix
  DataType = "unix-account-switch"
  Conditions = [ """"type":"wazuh-alerts"""", """"rule.description":"User successfully changed UID."""" ]
  Fields = ${WazuhParserTemplates.wazuh-common-fields.Fields} [
    """"predecoder.hostname":"({host}[^"]{1,2000})""",
    """({event_code}su)""",
    """"data.dstuser":"({account}[^"]{1,2000})""",
    """"data.srcuser":"({user}[^"]{1,2000})""",
  ]
  DupFields=["host->dest_host", "description->event_name"]
}
}
```