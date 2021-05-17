#### Parser Content
```Java
{
Name = q-leef-ds-account-disabled
  Vendor = StealthBits
  Product = StealthIntercept
  Lms = QRadar
  DataType = "account-disabled"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """LEEF:1.0|STEALTHbits|""","""cat=Account disabled""", """AttrOldValue=""", """Success=True""" ]
  Fields = [  
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) LEEF""",
    """devTime=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """usrName=(({domain}[^\\]{1,2000})\\)?({user}.+?)\s{1,100}\w+=""",
    """AffectedObject=(({target_domain}[^\\]{1,2000})\\)?({target_user}.+?)\s{1,100}\w+=""",
    """OrigServer=([^\\]{1,2000}\\)?({dest_host}.+?)\s{1,100}\w+="""
  ]
    DupFields = [ "dest_host->host" ]
}
```