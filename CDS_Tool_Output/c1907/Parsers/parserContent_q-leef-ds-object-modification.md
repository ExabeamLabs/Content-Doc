#### Parser Content
```Java
{
Name = q-leef-ds-object-modification
  Vendor = StealthBits
  Lms = QRadar
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """LEEF:1.0|STEALTHbits|""", """AttrNewValue=""", """Success=""" ]
  Fields = [  
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) LEEF""",
    """devTime=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """cat=({activity_type}.+?)\s+(\w+=|$)""",
    """usrName=(({domain}[^\\]+)\\)?({user}.+?)\s+(\w+=|$)""",
    """AffectedObject=(?:\t|([^\\]+\\)?({object}.+?))\s*(\w+=|$)""",
    """AttrName=(?:\t|({attribute}.+?))\s+(\w+=|$)""",
    """AttrOldValue=(?:\t|({old_attribute}.+?))\s+(\w+=|$)""",
    """AttrNewValue=(?:\t|({new_attribute}.+?))\s+(\w+=|$)""",
    """Success=({outcome}.+?)\s+(\w+=|$)""",
    """Success=False.+?Reason=({failure_reason}.+?)\s+(\w+=|$)""",
    """DistinguishedName=(.+?({object_dn}(CN|cn)=.+?,({object_ou}(OU|ou).+?(DC|dc)=[\w-]+))|(?:.+?))\s+(\w+=|$)""",
    """DistinguishedName=({object_dn}.+?)\s+(\w+=|$)""",
    """ClassName=({object_class}.+?)\s+OrigServer=""",
    """OrigServer=([^\\]+\\)?({dest_host}.+?)\s+(\w+=|$)"""
  ]
}
```