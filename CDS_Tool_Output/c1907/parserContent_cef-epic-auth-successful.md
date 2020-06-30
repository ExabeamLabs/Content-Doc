#### Parser Content
```Java
{
Name = cef-epic-auth-successful
  Vendor = Epic
  Product = Epic
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Epic|Security-SIEM|""", """|AUTHENTICATION|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """({host}[\w\-.]+)\s+CEF:""",
    """LOGINLDAPID=({user}[^\s]+)""",
    """workstationID=({dest_host}[\w\-.]+)""",
    """shost=({src_host}[\w\-.]+)""",
  ]
}
```