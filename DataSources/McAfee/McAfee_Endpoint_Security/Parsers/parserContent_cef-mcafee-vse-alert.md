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
      """\srt=({time}\d{1,100})""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\sdhost=({src_host}[^\s]{1,2000})""",
      """\sdst=(?:0.0.0.0|({src_ip}[\da-fA-F.:]{1,2000}))""",
      """\sfname=({malware_url}.+?\\+({malware_file_name}[^\\]{1,2000}?))\s{1,100}(\w+=|$)""",
      """\smsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
      """\sduser=(({domain}[^=\\]{1,2000})\\+)?({user}.+?)\s{1,100}(\w+=|$)""",
      """\sdntdom=(?:\(none\)|({domain}[^\s]{1,2000}))""",
      """\sexternalId=({alert_id}\d{1,100})""",
      """\|McAfee\|VirusScan[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_name}[^.|]{1,2000})""",
      """\scs1=(?:none|({alert_name}.+?))\s{1,100}(\w+=|$)""",
      """\scat=({threat_category}.+?)\s{1,100}(\w+=|$)""",
      """\|McAfee\|VirusScan[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_type}[^.|]{1,2000})""",
      """\|McAfee\|VirusScan[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_severity}[^\|]{1,2000})""",
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