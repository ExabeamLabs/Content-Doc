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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
    """LOGINLDAPID=({user}[^\s]{1,2000})""",
    """workstationID=({dest_host}[\w\-.]{1,2000})""",
    """shost=({src_host}[\w\-.]{1,2000})""",
    """IP=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """ROLE=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """USERJOB=({resource}.+?)\s{1,100}(\w+=|$)""",
    """LOGINERROR=({failure_reason}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```