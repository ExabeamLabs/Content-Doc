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
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """EventID=({event_code}\d+)""",
    """TimeGenerated=({time}\d{10})""",
    """Computer=({host}[^\s]+)""",
    """A member was added to a security-enabled ({group_type}[^\s]+) group.+?Account Name:\s*({user}[^\s]+).+?Account Domain:\s*({domain}[^\s]+).+?Logon ID:\s*({logon_id}[^\s]+)\s+""",
    """Member:\s*Security ID:\s*({account_id}.+?)\s*Account Name:""",
    """Member:\s*Security ID:\s*({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}.+?)|(?:[^\s]+))\s*Account Name:""",
    """Member:.*?Account Name:\s*(?:-|({account_dn}(CN|cn)=.+?,({account_ou}(OU|ou).+?(DC|dc)=[\w-]+)))?\s*Group:\s*Security ID:\s*({group_id}.+?)\s*(Group|Account) Name:\s*({group_name}.+?)?\s*(Group|Account) Domain:\s*({group_domain}.+?)\s*Additional Information:""",
  ]
  DupFields = [ "host->dest_host" ]
}
```