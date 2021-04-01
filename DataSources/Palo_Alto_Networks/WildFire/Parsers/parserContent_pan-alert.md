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
    """,THREAT,([^,]*?,){9}(?:\w+\\+)?({user}[^,]+)""",
    """,THREAT,([^,]*,){8}(({user_email}[^@,]+@[^\.,]+\.[^,]+)|(({domain}[^\\,]+)\\)?({user}[^,]+)),""",
    """,THREAT,(("[^"]*?",)|([^,]*,)){29}any,({alert_severity}low|medium|high|critical),""",
    """,THREAT,(("[^"]*?",)|([^,]*,)){30}({alert_severity}[^,]+),""", 
    """,THREAT,([^,]*,){20}(?:|({src_port}\d+)),(?:|({dest_port}\d+)),([^,]*,){3}(?:|({protocol}[^,]+)),(?:|({action}[^,]*)),""",
    """,THREAT,([^,]*,){27}"[^"]*?",({alert_name}[^,]+?)(\(({alert_id}\d+)\))?,""",
    """,THREAT,([^,]*,){27}\\?"+({alert_name}[^"]+)"+,"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```