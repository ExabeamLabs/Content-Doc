#### Parser Content
```Java
{
Name = pan-alert
  Vendor = Palo Alto Networks
  Product = WildFire
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,wildfire""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """,THREAT,({alert_type}.+?),\d+,({time}\d+/\d+/\d+\s+\d\d:\d\d:\d\d),({src_ip}[^,]*?),({dest_ip}[^,]*?),(("[^"]*?",)|([^,]*,)){22}("",|(("({malware_url}[^"]+)"|({=malware_url}[^,]+)),))({alert_name}[^,]+?),({alert_severity}[^,]+?),({additional_info}.+?),({alert_id}\d+)""",
    """,THREAT,([^,]*?,){9}(?:\w+\\+)?({user}[^,]+)""",
    """,THREAT,([^,]*?,){8}(?:\w+\\+)?({user}[^,]+)""",
    """,THREAT,(("[^"]*?",)|([^,]*,)){29}any,({alert_severity}low|medium|high|critical),""",
    """,THREAT,(("[^"]*?",)|([^,]*,)){30}({alert_severity}[^,]+),""", 
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```