#### Parser Content
```Java
{
Name = q-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-member-added"
  TimeFormat = "epoch_sec"
  Conditions = [ "A member was added to a security-enabled", "EventID=", "EventIDCode=", "TimeGenerated=" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]{1,2000} group)""",
    """EventID=({event_code}\d{1,100})""",
    """TimeGenerated=({time}\d{10})""",
    """Computer=({host}[^\s]{1,2000})""",
    """A member was added to a security-enabled ({group_type}[^\s]{1,2000}) group.+?Account Name:\s{0,100}({user}[^\s]{1,2000}).+?Account Domain:\s{0,100}({domain}[^\s]{1,2000}).+?Logon ID:\s{0,100}({logon_id}[^\s]{1,2000})\s{1,100}""",
    """Member:\s{0,100}Security ID:\s{0,100}({account_id}.+?)\s{0,100}Account Name:""",
    """Member:\s{0,100}Security ID:\s{0,100}({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}.+?)|(?:[^\s]{1,2000}))\s{0,100}Account Name:""",
    """Member:.*?Account Name:\s{0,100}(?:-|({account_dn}(CN|cn)=.+?,({account_ou}(OU|ou).+?(DC|dc)=[\w-]{1,2000})))?\s{0,100}Group:\s{0,100}Security ID:\s{0,100}({group_id}.+?)\s{0,100}(Group|Account) Name:\s{0,100}({group_name}.+?)?\s{0,100}(Group|Account) Domain:\s{0,100}({group_domain}.+?)\s{0,100}Additional Information:""",
  ]
  DupFields = [ "host->dest_host" ]


}
```