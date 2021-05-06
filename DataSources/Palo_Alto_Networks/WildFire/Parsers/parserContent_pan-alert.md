#### Parser Content
```Java
{
Name = pan-alert
  Vendor = Palo Alto Networks
  Product = WildFire
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """,THREAT,wildfire""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """\d\d:\d\d:\d\d\s({host}[\w.-]+)\s""",
    """THREAT,([^,]+,){2}({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """THREAT,({alert_type}[^,]+),[^,]+,({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z),({src_ip}[^,]*?),({dest_ip}[^,]*?),([^,]*?,)""",
    """THREAT,({alert_type}[^,]+),[^,]+,({time}\d+\/\d+\/\d+ \d+:\d+:\d+),({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),({dest_translate_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """,THREAT,([^,]*?,){9}(?:\w+\\+)?({user}[^,]+)""",
    """,THREAT,([^,]*,){8}(({user_email}[^@,]+@[^\.,]+\.[^,]+)|(({domain}[^\\,]+)\\)?({user}[^,]+)),""",
    """(?i),THREAT,(("[^"]*?",)|([^,]*,)){30,31}({alert_severity}low|medium|high|critical|informational),""",
    """,THREAT,([^,]*,){20}(?:|({src_port}\d+)),(?:|({dest_port}\d+)),([^,]*,){3}(?:|({protocol}[^,]+)),(?:|({action}[^,]*)),""",
    """,THREAT,([^,]*,){27}"[^"]*?",({alert_name}[^,]+?)\s*(\(({alert_id}\d+)\))?,""",
    """,THREAT,([^,]*,){27}\\?"*({alert_name}[^"]+?)\s*"+""",
    """(?i),THREAT,(("[^"]*?",)|([^,]*,)){30,31}(low|medium|high|critical|informational),({direction}[^,]*),([^,]+,){3}({src_location}[^\d,]+)""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```