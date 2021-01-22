#### Parser Content
```Java
{
Name = cef-epic-app-login
  Vendor = Epic
  Product = Epic
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Epic|Security-SIEM|""", """|LOGIN|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """({host}[\w\-.]+)\s+CEF:""",
    """LOGINLDAPID=({user}[^\s]+)""",
    """workstationID=({dest_host}[\w\-.]+)""",
    """shost=({src_host}[\w\-.]+)""",
    """IP=({dest_ip}[A-Fa-f:\d.]+)""",
    """ROLE=({additional_info}.+?)(\s+\w+=|\s*$)""",
    """USERJOB=(|({resource}.+?))\s+(\w+=|$)""",
  ]
}
```