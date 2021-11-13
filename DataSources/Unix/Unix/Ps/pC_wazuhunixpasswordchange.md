#### Parser Content
```Java
{
Name = wazuh-unix-password-change
  Product = Unix
  Vendor = Unix
  DataType = "password-change"
  Conditions = [ """"type":"wazuh-alerts"""", """"rule.description":"PAM: User changed password."""" ]
  Fields = ${WazuhParserTemplates.wazuh-common-fields.Fields} [
    """"predecoder.hostname":"({host}[^"]{1,2000})""",
    """"data.dstuser":"({target_user}[^"]{1,2000})""",
    """"agent\.labels\.network\.ipv4\.primary":"({src_ip}(\d{1,3}\.){3}\d{1,3})"""
]
  DupFields=["host->dest_host", "description->event_name"]


}
```