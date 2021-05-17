#### Parser Content
```Java
{
Name = q-leef-ds-object-modification
  Vendor = StealthBits
  Product = StealthIntercept
  Lms = QRadar
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """LEEF:1.0|STEALTHbits|""", """AttrNewValue=""", """Success=""" ]
  Fields = [  
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) LEEF""",
    """devTime=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """cat=({activity_type}.+?)\s{1,100}(\w+=|$)""",
    """usrName=(({domain}[^\\]{1,2000})\\)?({user}.+?)\s{1,100}(\w+=|$)""",
    """AffectedObject=(?:\t|([^\\]{1,2000}\\)?({object}.+?))\s{0,100}(\w+=|$)""",
    """AttrName=(?:\t|({attribute}.+?))\s{1,100}(\w+=|$)""",
    """AttrOldValue=(?:\t|({old_attribute}.+?))\s{1,100}(\w+=|$)""",
    """AttrNewValue=(?:\t|({new_attribute}.+?))\s{1,100}(\w+=|$)""",
    """Success=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """Success=False.+?Reason=({failure_reason}.+?)\s{1,100}(\w+=|$)""",
    """DistinguishedName=(.+?({object_dn}(CN|cn)=.+?,({object_ou}(OU|ou).+?(DC|dc)=[\w-]{1,2000}))|(?:.+?))\s{1,100}(\w+=|$)""",
    """DistinguishedName=({object_dn}.+?)\s{1,100}(\w+=|$)""",
    """ClassName=({object_class}.+?)\s{1,100}OrigServer=""",
    """OrigServer=([^\\]{1,2000}\\)?({dest_host}.+?)\s{1,100}(\w+=|$)"""
  ]
}
```