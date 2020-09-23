#### Parser Content
```Java
{
Name = cef-carbonblack-file-alert
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = ArcSight
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Carbon Black|Protection|""", " fname=" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\srt=({time}[\d]+)""",
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """(\||\s)dvc=(|({host_ip}.+?))\s+(\w+=|$)""",
    """(\||\s)dvchost=(|({host}.+?))\s+(\w+=|$)""",
    """(\||\s)dst=(|({dest_ip}.+?))\s+(\w+=|$)""",
    """(\||\s)dhost=(|(\S+\\+)?({dest_host}.+?))\s+(\w+=|$)""",
    """(\||\s)duser=(|(({domain}NT AUTHORITY|[^\s\\]+)\\+)?({user}.+?))\s+(\w+=|$)""",
    """(\||\s)externalId=(|({alert_id}.+?))\s+(\w+=|$)""",
    """\|Carbon Black\|Protection\|(.*?\|){2}({alert_name}[^\|]+)\|""",
    """\|Carbon Black\|Protection\|(.*?\|){2}({accesses}[^\|]+)\|""",
    """\|Carbon Black\|Protection\|(.*?\|){2}({accesses}[^\|]+?)(\s*\([^|]+)?\|""",
    """(\||\s)cat=(|({alert_type}.+?))\s+(\w+=|$)""",
    """(\||\s)deviceProcessName=(|({process}.+?))\s+(\w+=|$)""",
    """(\||\s)filePath=(|({file_path}(({file_parent}[^=]+[^\\])\\+)?({file_name}.+?)))\s+(\w+=|$)""",
    """(\||\s)fname=(|({file_name}.+?))\s+(\w+=|$)""",
    """(\||\s)fileHash=(|({old_hash}.+?))\s+(\w+=|$)""",
  ]
  DupFields = [ "old_hash->new_hash" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]}
```