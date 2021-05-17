#### Parser Content
```Java
{
Name = cef-bit9-file-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = ArcSight
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "MM dd yyyy HH:mm:ss"
  Conditions = [ """|Bit9|Security Platform|""", " fname=" ]
  Fields = [
    """({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """exabeam_\w+=({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """(\||\s)dvc=(|({host}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)dvchost=(|({host}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)dst=(|({dest_ip}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)dhost=(|(\S+\\+)?({dest_host}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)duser=(|(({domain}NT AUTHORITY|[^\s\\]{1,2000})\\+)?({user}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)externalId=(|({alert_id}.+?))\s{1,100}(\w+=|$)""",
    """\|Bit9\|Security Platform\|(.*?\|){2}({alert_name}[^\|]{1,2000})\|""",
    """\|Bit9\|Security Platform\|(.*?\|){2}({accesses}[^\|]{1,2000})\|""",
    """\|Bit9\|Security Platform\|(.*?\|){2}({accesses}[^\|]{1,2000}?)(\s{0,100}\([^|]{1,2000})?\|""",
    """\s<USER:({alert_severity}.+?)>\s""",
    """(\||\s)cat=(|({alert_type}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)deviceProcessName=(|({process}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)filePath=(|({file_path}(({file_parent}[^=]{1,2000}[^\\])\\+)?({file_name}.+?)))\s{1,100}(\w+=|$)""",
    """(\||\s)fname=(|({file_name}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)fileHash=(|({old_hash}.+?))\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "old_hash->new_hash" ]
}
```