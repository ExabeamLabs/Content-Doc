#### Parser Content
```Java
{
Name = imanage-dlp-alert
  Vendor = iManage
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """DOCNUM:""", """DOCUSER:""" ]
  Fields = [
    """"\s*DOCNUM:\s*"+({file_name}[^"\s]+)"+""",
    """"\s*ACTIVITY:\s*"+({alert_type}[^"\s]+)"+""",
    """"\s*ACTIVITY_DATETIME:\s*"+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d)""",
    """"\s*DOCUSER:\s*"+({user}[^":]+)"+""",
    """"\s*APPNAME:\s*"+({app}[^":]+)"+""",
    """"\s*LOCATION:\s*"+({host}[^":]+)"+"""
  ]
}

{
  Name = badgepoint-physical-badge-access
  Vendor = Badgepoint
  Product = Badgepoint
  Lms = Direct
  DataType = "physical-access"
  TimeFormat =  "dd/MM/yyyy:HH:mm:ss z"
  Conditions = [ """<badgepoint_conditions>""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """([^\|]*\|){6}({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d \w+)""",
    """({badge_id}[^\|\s=]+)\|""",
    """([^\|]*\|){1}({last_name}[^\|]+)\|({first_name}[^\|]+)""",
    """([^\|]*\|){3}({location_door}[^\|]+\|[^\|]+)""",
    """([^\|]*\|){5}({outcome}[^\|]+)""",
  ]
}
```