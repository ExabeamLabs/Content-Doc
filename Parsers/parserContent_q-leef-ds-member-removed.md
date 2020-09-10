#### Parser Content
```Java
{
Name = q-leef-ds-member-removed
  Vendor = StealthBits
  Lms = QRadar
  DataType = "member-removed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """LEEF:1.0|STEALTHbits|""","""cat=Group Members Removed""", """AttrOldValue=""", """Success=True""" ]
  Fields = [  
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) LEEF""",
    """devTime=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """usrName=(({domain}[^\\]+)\\)?({user}.+?)\s+\w+=""",
    """AffectedObject=(({group_domain}[^\\]+)\\)?({group_name}.+?)\s+\w+=""",
    """DistinguishedName=(({group_dn}CN=.+?,({group_ou}OU.+?DC=.+?))|(?:.+?))\s+\w+=""",
    """AttrNewValue=(({account_dn}CN=.+?({account_ou}OU.+?DC=.+?))|(?:.+?))\s+\w+=""",
    """OrigServer=([^\\]+\\)?({dest_host}.+?)\s+\w+="""
  ]
}
```