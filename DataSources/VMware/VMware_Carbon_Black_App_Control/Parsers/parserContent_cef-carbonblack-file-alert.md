#### Parser Content
```Java
{
Name = cef-carbonblack-file-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = ArcSight
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Carbon Black|Protection|""", " fname=" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\srt=({time}[\d]+)""",
    """exabeam_host=([^=]+?@\s{0,100})?({host}[^\s]+)""",
    """(\||\s)dvc=(|({host_ip}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)dvchost=(|({host}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)dst=(|({dest_ip}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)dhost=(|(\S+\\+)?({dest_host}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)duser=(|(({domain}NT AUTHORITY|[^\s\\]+)\\+)?({user}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)externalId=(|({alert_id}.+?))\s{1,100}(\w+=|$)""",
    """\|Carbon Black\|Protection\|(.*?\|){2}({alert_name}[^\|]+)\|""",
    """\|Carbon Black\|Protection\|(.*?\|){2}({accesses}[^\|]+)\|""",
    """\|Carbon Black\|Protection\|(.*?\|){2}({accesses}[^\|]+?)(\s{0,100}\([^|]+)?\|""",
    """(\||\s)cat=(|({alert_type}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)deviceProcessName=(|({process}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)filePath=(|({file_path}(({file_parent}[^=]+[^\\])\\+)?({file_name}.+?)))\s{1,100}(\w+=|$)""",
    """(\||\s)fname=(|({file_name}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)fileHash=(|({old_hash}.+?))\s{1,100}(\w+=|$)""",
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