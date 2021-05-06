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
    """exabeam_host=({host}[^\s]+)""",
    """"host":\{.*?"name":"({host}[^"]+)".*?\}""",
    """({host}[\w\-\.]+)\s+\d+,[^,]*,[^,]*,THREAT,virus,""",
    """THREAT,({alert_type}virus),\d+,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),([^,]*,){3}(({src_domain}[^\\,]+)\\)?(?:|({src_user}[^,]+)),(({domain}[^\\,]+)\\)?(?:|({user}[^,]+)),""",
    """,THREAT,.+?,({action}[^,]+),\\?"[^"]*"""",
    """,THREAT,.+?,\\?"(|({malware_url}.+?))\\?",""",
    """,THREAT,.+?,\\?"[^"]*",({alert_name}[^,]+),""",
    """,THREAT,.+?,\\?"[^"]*",[^,]*,(unknown|({threat_category}[^,]+)),""",
    """THREAT,virus,.+?,\\?"[^"]*",([^,]*,){2}({alert_severity}[^,]+),""",
    """THREAT,virus,.+?,\\?"[^"]*",([^,]*,){4}({alert_id}[^,]+),""",
    """(?i),THREAT,(("[^"]*?",)|([^,]*,)){30,31}(low|medium|high|critical|informational),({direction}[^,]*),([^,]+,){3}({src_location}[^\d,]+)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_id->sourceId", "alert_type->malwareCategory", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address"]}
```