#### Parser Content
```Java
{
Name = symantec-epp-cef-alert
  Conditions = ["""|Symantec|Endpoint Protection|"""]
  Fields = ${SymantecParserTemplates.symantec-epp-cef-alert-1.Fields} [
    """\scatdt=({category}[^=]+?)\s{1,100}(\w+=|$)""",
    """\scs6=({category}[^=]+?)\s{1,100}(\w+=|$)""",
    """\scn1=({viruses_num}\d{1,100})""",
  ]
  SOAR {
    IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
      NameTemplate = """Symantec Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
symantec-epp-cef-alert-1 = {
    Vendor = Symantec
    Product = Symantec Endpoint Protection
    Lms = ArcSight
    DataType = "alert"
    TimeFormat = "epoch"
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\scs1=({alert_name}[^=]+?)\s{1,100}(\w+=|$)""",
      """\sduser=((?i)(system|none)|({user}[^=]+?))\s{1,100}(\w+=|$)""",
      """\ssuser=((?i)(system|none)|({user}[^=]+?))\s{1,100}(\w+=|$)""",
      """\sfname=\w:\\+[uU]sers\\+({user}[^\\]+)""",
      """\sfname=[\s ]*({malware_file_name}[^=]+?)\s{1,100}(\w+=|$)""",
      """\seventId=({alert_id}\d{1,100})""",
      """\sdvc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sahost=({host}[^\s]+)""",
      """\sdvchost=({host}[^\s]+)""",
      """\sdhost=({src_host}[^\s]+)""",
      """\sdst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\|Symantec\|Endpoint Protection\|([^|]*?\|){2}({alert_type}[^|(]+?)\s{0,100}(\([^|]*?)?\|(Unknown|({alert_severity}[^|]+))\|""",
      """\scat=({scan_type}[^=]+?)\s{1,100}(\w+=|$)""",
      """\sfilePath=({malware_url}[^=]+?)\s{1,100}\w+=""",
      """\sfileHash=({md5}[^\s]+)""",
      """\scs2=({outcome}[^=]+?)\s{1,100}(\w+=|$)""",
      """\scs3=({secondary_action}[^=]+?)\s{1,100}(\w+=|$)""",
      """\scs5=((?i)(\(Unknown\) \[-1\])|({process_name}[^=]+?))\s{1,100}(\w+=|$)""",
    ]

```