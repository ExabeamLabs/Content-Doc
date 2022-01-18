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
    """({event_name}A member was added to a security-enabled [\w\s]{1,2000} group)""",
    """"MachineName":"({host}[^."]{1,2000})""",
    """"TimeGenerated":"({time}[^"]{0,2000})""",
    """"InstanceId":"({event_code}[^"]{1,2000})""",
    """"Message":"A member was added to a security-enabled ({group_type}[^\s]{1,2000}) group.""",
    """"6":"({user}[^"]{1,2000})""",
    """"5":"({user_sid}[^"]{1,2000})""",
    """"7":"({domain}[^"]{1,2000})""",
    """"8":"({logon_id}[^"]{1,2000})""",
    """"2":"({group_name}[^"]{1,2000})""",
    """"3":"({group_domain}[^"]{1,2000})""",
    """"1":"({account_id}[^"]{1,2000})""",
    """"0":"({account_dn}[^"]{1,2000})""",
    """"0":"CN=.*,({account_ou}OU=.+?DC=.+?[^"]{1,2000})""",
  ]
  DupFields = [ "host->dest_host" ]


}
```