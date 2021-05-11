#### Parser Content
```Java
{
Name = cef-epic-auth-successful
  Vendor = Epic
  Product = Epic SIEM
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Epic|Security-SIEM|""", """|AUTHENTICATION|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """({host}[\w\-.]+)\s{1,100}CEF:""",
    """LOGINLDAPID=({user}[^\s]+)""",
    """workstationID=({dest_host}[\w\-.]+)""",
    """shost=({src_host}[\w\-.]+)""",
  ]
}
```