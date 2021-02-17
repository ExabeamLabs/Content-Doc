#### Parser Content
```Java
{
Name = cef-mcafee-vse-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = ArcSight
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """|McAfee|VirusScan Enterprise|""", " cat=" ]
    Fields = [
      """\srt=({time}\d+)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]+)""",
      """\sdhost=({src_host}[^\s]+)""",
      """\sdst=(?:0.0.0.0|({src_ip}[\da-fA-F.:]+))""",
      """\sfname=({malware_url}.+?\\+({malware_file_name}[^\\]+?))\s+(\w+=|$)""",
      """\smsg=({additional_info}.+?)\s+(\w+=|$)""",
      """\sduser=(({domain}[^=\\]+)\\+)?({user}.+?)\s+(\w+=|$)""",
      """\sdntdom=(?:\(none\)|({domain}[^\s]+))""",
      """\sexternalId=({alert_id}\d+)""",
      """\|McAfee\|VirusScan.+?\|.+?\|.+?\|({alert_name}[^.|]+)""",
      """\scs1=(?:none|({alert_name}.+?))\s+(\w+=|$)""",
      """\scat=({threat_category}.+?)\s+(\w+=|$)""",
      """\|McAfee\|VirusScan.+?\|.+?\|.+?\|({alert_type}[^.|]+)""",
      """\|McAfee\|VirusScan.+?\|.+?\|.+?\|.+?\|({alert_severity}[^\|]+)""",
      """\ssproc=({process_name}.*?)\s\w+=""",
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```