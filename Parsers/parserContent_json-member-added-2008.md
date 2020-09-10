#### Parser Content
```Java
{
Name = json-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "MM/dd/yyyy H:mm:ss a"
  Conditions = [ """"Message":"A member was added to a security-enabled """, """"InstanceId":""", """"EntryType"""" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """"MachineName":"({host}[^."]+)""",
    """"TimeGenerated":"({time}[^"]*)""",
    """"InstanceId":"({event_code}[^"]+)""",
    """"Message":"A member was added to a security-enabled ({group_type}[^\s]+) group.""",
    """"6":"({user}[^"]+)""",
    """"5":"({user_sid}[^"]+)""",
    """"7":"({domain}[^"]+)""",
    """"8":"({logon_id}[^"]+)""",
    """"2":"({group_name}[^"]+)""",
    """"3":"({group_domain}[^"]+)""",
    """"1":"({account_id}[^"]+)""",
    """"0":"({account_dn}[^"]+)""",
    """"0":"CN=.*,({account_ou}OU=.+?DC=.+?[^"]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```