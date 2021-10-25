#### Parser Content
```Java
{
Name = wazuh-unix-sudo-su
  Product = Unix
  Vendor = Unix
  DataType = "unix-account-switch"
  Conditions = [ """"type":"wazuh-alerts"""", "session opened for user","sudo su", """(uid=""" ]
  Fields = ${WazuhParserTemplates.wazuh-common-fields.Fields} [
    """"predecoder.hostname":"({host}[^"]{1,2000})""",
    """({event_code}sudo su)""",
    """"data.dstuser":"({account}[^"]{1,2000})""",
    """"data.srcuser":"({user}[^"]{1,2000})""",
    """"data.uid":"({user_uid}[^"]{1,2000})"""
  ]
  DupFields=["host->dest_host", "description->event_name"]
}
```