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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
    """LOGINLDAPID=({user}[^\s]{1,2000})""",
    """workstationID=({dest_host}[\w\-.]{1,2000})""",
    """shost=({src_host}[\w\-.]{1,2000})""",
  ]


}
```