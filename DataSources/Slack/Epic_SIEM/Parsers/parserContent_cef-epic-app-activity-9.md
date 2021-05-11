#### Parser Content
```Java
{
Name = cef-epic-app-activity-9
  Product = Epic SIEM
  Conditions = [ """CEF:""", """|Epic|Security-SIEM|""", """|CONTEXTCHANGE|""" ]
  Fields = ${EpicParserTemplates.cef-epic-app-activity.Fields} [
    """PREVDEPARTMENT=({object}.+?)\s{1,100}(\w+=|$)""",
    """NEWDEPARTMENT=({resource}.+?)\s{1,100}(\w+=|$)""",
  ]
}
cef-epic-app-activity = {
  Vendor = Epic
  Product = Epic SIEM
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+)\s{1,100}CEF:""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """workstationID=({dest_host}[\w\-.]+)""",
    """shost=({src_host}[\w\-.]+)""",
    """flag=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """MASKMODE=({result}.+?)\s{1,100}(\w+=|$)""",
    """PREVUSER=({user}[^\s,]+)""",
    """NEWUSER=({account}[^\s,]+)""",
  ]

```