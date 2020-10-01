#### Parser Content
```Java
{
Name = cef-epic-failed-app-login
  Vendor = Epic
  Product = Epic SIEM
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Epic|Security-SIEM|""", """|FAILEDLOGIN|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """({host}[\w\-.]+)\s+CEF:""",
    """LOGINLDAPID=({user}[^\s]+)""",
    """workstationID=({dest_host}[\w\-.]+)""",
    """shost=({src_host}[\w\-.]+)""",
    """IP=({dest_ip}[A-Fa-f:\d.]+)""",
    """ROLE=({additional_info}.+?)\s+(\w+=|$)""",
    """USERJOB=({resource}.+?)\s+(\w+=|$)""",
    """LOGINERROR=({failure_reason}.+?)\s+(\w+=|$)""",
  ]
}
```