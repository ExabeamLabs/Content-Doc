#### Parser Content
```Java
{
Name = wazuh-unix-chkpwd-fail
  Product = Unix
  Vendor = Unix
  DataType = "authentication-failed"
  Conditions = [ """"type":"wazuh-alerts"""", """"rule.description":"unix_chkpwd: Password check failed."""" ]
  Fields = ${WazuhParserTemplates.wazuh-common-fields.Fields} [
    """"predecoder.hostname":"({host}[^"]{1,2000})""",
    """password check failed for user \(({user}[^)]{1,2000})"""
  ]
  DupFields=["host->dest_host", "description->event_name"]


}
```