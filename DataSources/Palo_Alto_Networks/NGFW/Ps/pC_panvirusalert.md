#### Parser Content
```Java
{
Name = pan-virus-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,virus,""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"host":\{[^=]{0,2000}?"name":"({host}[^"]{1,2000})"[^=]{0,2000}?\}""",
    """({host}[\w\-\.]{1,2000})\s{1,100}\d{1,100},[^,]{0,2000},[^,]{0,2000},THREAT,virus,""",
    """,THREAT,([^,]{0,2000}.){55}({host}[^,]{1,2000}),""",
    """THREAT,({alert_type}virus),\d{1,100},({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),([^,]{0,2000},){3}(({domain}[^\\,]{1,2000})\\)?(?:|({user}[^,]{1,2000})),(({target_domain}[^\\,]{1,2000})\\)?(?:|({target_user}[^,]{1,2000})),""",
    """,THREAT,.+?,({action}[^,]{1,2000}),\\?"[^"]{0,2000}"""",
    """,THREAT,.+?,\\?"(|({malware_url}[^\s]{1,2000}?))\\?",""",
    """,THREAT,.+?,\\?"[^"]{0,2000}",({alert_name}[^,]{1,2000}),""",
    """,THREAT,.+?,\\?"[^"]{0,2000}",[^,]{0,2000},(unknown|({category}[^,]{1,2000})),""",
    """THREAT,virus,.+?,\\?"[^"]{0,2000}",([^,]{0,2000},){2}({alert_severity}[^,]{1,2000}),""",
    """THREAT,virus,.+?,\\?"[^"]{0,2000}",([^,]{0,2000},){4}({alert_id}[^,]{1,2000}),""",
    """(?i),THREAT,(("[^"]{0,2000}?",)|([^,]{0,2000},)){30,31}(low|medium|high|critical|informational),({direction}[^,]{0,2000}),([^,]{1,2000},){3}({src_location}[^\d,]{1,2000})""",
    """THREAT,virus,(("[^"]{1,2000}?"|[^,]{0,2000}),){64}({threat_category}[^,]{1,2000}),"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_id->sourceId", "alert_type->malwareCategory", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address"]}
```