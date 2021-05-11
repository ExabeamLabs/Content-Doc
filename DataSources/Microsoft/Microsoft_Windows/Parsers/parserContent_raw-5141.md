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
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}""",
    """({event_code}5141)""",
    """(?i)(success|failure|audit)\s{1,100}\w+\s{1,100}({host}[\w\-.]+)""",
    """Subject:.+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]+)""",
    """Object:.+?Class:\s{1,100}({object_class}.+?)\s{1,100}Operation:""",
    """Object:\s{1,100}DN:\s{1,100}({object_dn}.+?)\s{1,100}GUID:""",
    """Object:\s{1,100}DN:.+?({object_ou}OU.+?)\s{1,100}GUID:""",
    """Account Name:\s{0,100}(|({user}.+?))\s{1,100}Account Domain:\s{0,100}(|({domain}[^\s]+))\s{1,100}Logon ID:\s{0,100}(|({logon_id}[^\s]+))\s{1,100}Target Account:""",
    """Target\sAccount.+?Security ID:\s{0,100}({target_sid}[^\s]+)\s""",
    """Target\sAccount.+?Account Name:\s{0,100}({target_user}[^\s]+)\s""",
    """Target\sAccount.+?Account Domain:\s{0,100}({target_domain}[^\s]+)\s""",
    """User Account Control:\s{0,100}.+?\-\s({status}[^\s]+)\s""",
    """Changed Attributes:\s{0,100}(|({attribute}[^\s]+))\s{1,100}SAM Account Name""",
    """\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))"""
  ]
  DupFields = [ "host->dest_host" ]
}
```