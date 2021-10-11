#### Parser Content
```Java
{
Name = cef-epic-app-activity-6
  Product = Epic SIEM
  Conditions = [ """CEF:""", """|Epic|Security-SIEM|""", """|IC_SERVICE_AUDIT|""" ]
  Fields = ${EpicParserTemplates.cef-epic-app-activity.Fields} [
    """SERVICENAME=({object}.+?)\s{1,100}(\w+=|$)""",
  ]
}
cef-epic-app-activity = {
  Vendor = Epic
  Product = Epic SIEM
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
    """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """workstationID=({dest_host}[\w\-.]{1,2000})""",
    """shost=({src_host}[\w\-.]{1,2000})""",
    """flag=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """MASKMODE=({result}.+?)\s{1,100}(\w+=|$)""",
    """PREVUSER=({user}[^\s,]{1,2000})""",
    """NEWUSER=({account}[^\s,]{1,2000})""",
  ]

```