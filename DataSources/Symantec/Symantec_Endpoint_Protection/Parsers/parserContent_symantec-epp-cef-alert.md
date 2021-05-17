#### Parser Content
```Java
{
Name = symantec-epp-cef-alert
  Conditions = ["""|Symantec|Endpoint Protection|"""]
  Fields = ${SymantecParserTemplates.symantec-epp-cef-alert-1.Fields} [
    """\scatdt=({category}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\scs6=({category}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
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
      """\scs1=({alert_name}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
      """\sduser=((?i)(system|none)|({user}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
      """\ssuser=((?i)(system|none)|({user}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
      """\sfname=\w:\\+[uU]sers\\+({user}[^\\]{1,2000})""",
      """\sfname=[\s ]{0,2000}({malware_file_name}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
      """\seventId=({alert_id}\d{1,100})""",
      """\sdvc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sahost=({host}[^\s]{1,2000})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\sdhost=({src_host}[^\s]{1,2000})""",
      """\sdst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\|Symantec\|Endpoint Protection\|([^|]{0,2000}?\|){2}({alert_type}[^|(]{1,2000}?)\s{0,100}(\([^|]{0,2000}?)?\|(Unknown|({alert_severity}[^|]{1,2000}))\|""",
      """\scat=({scan_type}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
      """\sfilePath=({malware_url}[^=]{1,2000}?)\s{1,100}\w+=""",
      """\sfileHash=({md5}[^\s]{1,2000})""",
      """\scs2=({outcome}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
      """\scs3=({secondary_action}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
      """\scs5=((?i)(\(Unknown\) \[-1\])|({process_name}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    ]

```