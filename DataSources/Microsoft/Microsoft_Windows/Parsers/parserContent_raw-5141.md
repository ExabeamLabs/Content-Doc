#### Parser Content
```Java
{
Name = raw-5141
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "ds-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """A directory service object was deleted""", """Account Name:""" ]
  Fields = [
    """({event_name}A directory service object was deleted)""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s+""",
    """({event_code}5141)""",
    """(?i)(success|failure|audit)\s+\w+\s+({host}[\w\-.]+)""",
    """Subject:.+?Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """Object:.+?Class:\s+({object_class}.+?)\s+Operation:""",
    """Object:\s+DN:\s+({object_dn}.+?)\s+GUID:""",
    """Object:\s+DN:.+?({object_ou}OU.+?)\s+GUID:""",
    """Account Name:\s*(|({user}.+?))\s+Account Domain:\s*(|({domain}[^\s]+))\s+Logon ID:\s*(|({logon_id}[^\s]+))\s+Target Account:""",
    """Target\sAccount.+?Security ID:\s*({target_sid}[^\s]+)\s""",
    """Target\sAccount.+?Account Name:\s*({target_user}[^\s]+)\s""",
    """Target\sAccount.+?Account Domain:\s*({target_domain}[^\s]+)\s""",
    """User Account Control:\s*.+?\-\s({status}[^\s]+)\s""",
    """Changed Attributes:\s*(|({attribute}[^\s]+))\s+SAM Account Name""",
    """\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))"""
  ]
  DupFields = [ "host->dest_host" ]
}
```