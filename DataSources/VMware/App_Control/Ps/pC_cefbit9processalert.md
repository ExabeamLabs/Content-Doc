#### Parser Content
```Java
{
Name = cef-bit9-process-alert
  Vendor = VMware
  Product = App Control
  Lms = ArcSight
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "MM dd yyyy HH:mm:ss"
  Conditions = [ """|Bit9|Security Platform|""", "|Carbon Black watchlist|" ]
  Fields = [
    """({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """(exabeam_\w+=|^)({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """(\||\s)cs5=(|({alert_name}.+?))\s{1,100}([\w-]{1,2000}=|$)""",
    """(\||\s)externalId=({alert_id}.+?)(\s{1,100}[\w-]{1,2000}=|\s{0,100}$)""",
    """(\||\s)cat=(|({alert_type}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)deviceProcessName =({process}.+?)\s{1,100}?([\w-]{1,2000}=|$)""",
    """(\||\s)deviceProcessName =.+?({process_name}[^\\]{1,2000}?)\s{1,100}([\w-]{1,2000}=|$)""",
    """(\||\s)deviceProcessName =({directory}.+?)\\+[^\\]{1,2000}\s{1,100}([\w-]{1,2000}=|$)""",
    """(\||\s)dst=(|({dest_ip}.+?))(\s{1,100}[\w-]{1,2000}=|\s{0,100}$)""",
    """(\||\s)dhost=(|(\S+\\+)?({dest_host}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)duser=(|(({domain}[^\s\\]{1,2000})\\+)?({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """(\||\s)dvchost=(|({host}.+?))(\s\w+=|\s{0,100}$)""",
    """(\||\s)msg=.+?for process\s{1,100}'.+?'\s{1,100}\[({md5}[a-fA-F0-9]{1,2000})\]""",
    """(\||\s)sproc=({process_guid}.+?)(\s{1,100}[\w-]{1,2000}=|\s{0,100}$)""",
  ]
  DupFields = [ "process->path","directory->process_directory" ]
  SOAR {
      IncidentType = "generic"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description"]
      NameTemplate = """Carbon Black Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]

}
```