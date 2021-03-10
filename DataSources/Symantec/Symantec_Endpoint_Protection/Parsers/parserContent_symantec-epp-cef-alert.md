#### Parser Content
```Java
{
Name = symantec-epp-cef-alert
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = ["""|Symantec|Endpoint Protection|"""]
  Fields = [ 
             """\srt=({time}\d+)""",
             """\scs1=({alert_name}.+?)\s+(\w+=|$)""",
             """\sduser=(SYSTEM|system|({user}.+?))\s+(\w+=|$)""",
             """\ssuser=(SYSTEM|system|({user}.+?))\s+(\w+=|$)""",
             """\sfname=\w:\\+[uU]sers\\+({user}[^\\]+)""",
             """\sfname=[\s ]*({malware_file_name}.+?)\s+(\w+=|$)""",
             """\seventId=({alert_id}\d+)""",
             """\sdvc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """\sdvchost=({host}.+?)\s+(\w+=|$)""",
             """\sdhost=({src_host}.+?)\s+(\w+=|$)""",
             """\sdst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """\|Symantec\|Endpoint Protection\|[^\|]*\|\d+:\d+\|({alert_type}[^|]+)\|(Unknown|({alert_severity}[^|]+))\|""",
             """\scat=({scan_type}.+?)\s+(\w+=|$)""",
             """\sfilePath=({malware_url}.+?)\s+\w+=""",
             """\sfileHash=({md5}.+?)\s+(\w+=|$)""",
             """\scs2=({outcome}.+?)\s+(\w+=|$)""",
             """\scs3=({secondary_action}.+?)\s+(\w+=|$)""",
             """\scs5=({process_name}.+?)\s+(\w+=|$)""",
             """\scs6=({category}.+?)\s+(\w+=|$)""",
             """\scn1=({viruses_num}.+?)\s+(\w+=|$)""",
           ]
           DupFields = [ "alert_type->protection_name" ]
         SOAR {
          IncidentType = "malware"
          DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
          NameTemplate = """Symantec Alert ${alert_name} found"""
          ProjectName = "SOC"
          EntityFields = [
            {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```