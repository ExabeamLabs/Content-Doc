#### Parser Content
```Java
{
Name = cef-bit9-process-alert
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = ArcSight
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "MM dd yyyy HH:mm:ss"
  Conditions = [ """|Bit9|Security Platform|""", "|Carbon Black watchlist|" ]
  Fields = [
    """(exabeam_\w+=|^)({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """(\||\s)cs5=(|({alert_name}.+?))\s+([\w-]+=|$)""",
    """(\||\s)externalId=({alert_id}.+?)(\s+[\w-]+=|\s*$)""",
    """(\||\s)cat=(|({alert_type}.+?))\s+(\w+=|$)""",
    """(\||\s)deviceProcessName=({process}.+?)\s+?([\w-]+=|$)""",
    """(\||\s)deviceProcessName=.+?({process_name}[^\\]+?)\s+([\w-]+=|$)""",
    """(\||\s)deviceProcessName=({directory}.+?)\\+[^\\]+\s+([\w-]+=|$)""",
    """(\||\s)dst=(|({dest_ip}.+?))(\s+[\w-]+=|\s*$)""",
    """(\||\s)dhost=(|(\S+\\+)?({dest_host}.+?))\s+(\w+=|$)""",
    """(\||\s)duser=(|(({domain}[^\s\\]+)\\+)?({user}.+?))(\s+\w+=|\s*$)""",
    """(\||\s)dvchost=(|({host}.+?))(\s\w+=|\s*$)""",
    """(\||\s)msg=.+?for process\s+'.+?'\s+\[({md5}[a-fA-F0-9]+)\]""",
    """(\||\s)sproc=({process_guid}.+?)(\s+[\w-]+=|\s*$)""",
  ]
  DupFields = [ "process->path","directory->process_directory" ]
  SOAR {
      IncidentType = "generic"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description"]
      NameTemplate = """Carbon Black Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]}
```