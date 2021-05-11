#### Parser Content
```Java
{
Name = q-leef-ds-member-added
  Vendor = StealthBits
  Product = StealthIntercept
  Lms = QRadar
  DataType = "member-added"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """LEEF:1.0|STEALTHbits|""","""cat=Group Members Added""", """AttrOldValue=""", """Success=True""" ]
  Fields = [  
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) LEEF""",
    """devTime=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """usrName=(({domain}[^\\]+)\\)?({user}.+?)\s{1,100}\w+=""",
    """AffectedObject=(({group_domain}[^\\]+)\\)?({group_name}.+?)\s{1,100}\w+=""",
    """DistinguishedName=(({group_dn}CN=.+?,({group_ou}OU.+?DC=.+?))|(?:.+?))\s{1,100}\w+=""",
    """AttrNewValue=(({account_dn}CN=.+?({account_ou}OU.+?DC=.+?))|(?:.+?))\s{1,100}\w+=""",
    """OrigServer=([^\\]+\\)?({dest_host}.+?)\s{1,100}\w+="""
  ]
}
```