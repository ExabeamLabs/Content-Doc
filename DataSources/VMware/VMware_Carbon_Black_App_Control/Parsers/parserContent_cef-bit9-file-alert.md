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
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """(\||\s)dvc=(|({host}.+?))\s+(\w+=|$)""",
    """(\||\s)dvchost=(|({host}.+?))\s+(\w+=|$)""",
    """(\||\s)dst=(|({dest_ip}.+?))\s+(\w+=|$)""",
    """(\||\s)dhost=(|(\S+\\+)?({dest_host}.+?))\s+(\w+=|$)""",
    """(\||\s)duser=(|(({domain}NT AUTHORITY|[^\s\\]+)\\+)?({user}.+?))\s+(\w+=|$)""",
    """(\||\s)externalId=(|({alert_id}.+?))\s+(\w+=|$)""",
    """\|Bit9\|Security Platform\|(.*?\|){2}({alert_name}[^\|]+)\|""",
    """\|Bit9\|Security Platform\|(.*?\|){2}({accesses}[^\|]+)\|""",
    """\|Bit9\|Security Platform\|(.*?\|){2}({accesses}[^\|]+?)(\s*\([^|]+)?\|""",
    """\s<USER:({alert_severity}.+?)>\s""",
    """(\||\s)cat=(|({alert_type}.+?))\s+(\w+=|$)""",
    """(\||\s)deviceProcessName=(|({process}.+?))\s+(\w+=|$)""",
    """(\||\s)filePath=(|({file_path}(({file_parent}[^=]+[^\\])\\+)?({file_name}.+?)))\s+(\w+=|$)""",
    """(\||\s)fname=(|({file_name}.+?))\s+(\w+=|$)""",
    """(\||\s)fileHash=(|({old_hash}.+?))\s+(\w+=|$)""",
  ]
  DupFields = [ "old_hash->new_hash" ]
}
```