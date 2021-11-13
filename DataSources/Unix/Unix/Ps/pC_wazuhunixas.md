#### Parser Content
```Java
{
Name = wazuh-unix-as
  Product = Unix
Vendor = Unix
DataType = "unix-account-switch"
  Conditions = [ """"type":"wazuh-alerts"""", "session opened for user", "(uid=", "sshd:", "_unix" ]
Fields = ${WazuhParserTemplates.wazuh-common-fields.Fields} [
    """session opened for user ({user}[^\s]{1,2000}?) by""",
    """"predecoder.hostname":"({host}[^"]{1,2000})""",
    """({event_code}ssh)""",
    """"data.dstuser":"({account}[^"]{1,2000})""",
    """"data.uid":"({user_uid}[^"]{1,2000})""",
    """sshd\[({logon_id}\d{1,100})""",
  ]
  DupFields = [ "host->dest_host", "user_uid->user_id", "description->event_name"]


}
```