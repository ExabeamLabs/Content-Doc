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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """\d\d:\d\d:\d\d\s({host}[\w.-]{1,2000})\s""",
    """THREAT,({alert_type}[^,]{1,2000}),[^,]{1,2000},({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z),({src_ip}[^,]{0,2000}?),({dest_ip}[^,]{0,2000}?),([^,]{0,2000}?,)""",
    """THREAT,({alert_type}[^,]{1,2000}),[^,]{1,2000},({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}),({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),({dest_translate_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """THREAT,([^,]{1,2000},){2}({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,THREAT,([^,]{0,2000}?,){9}(?:\w+\\+)?({user}[^,]{1,2000})""",
    """,THREAT,([^,]{0,2000},){8}(({user_email}[^@,]{1,2000}@[^\.,]{1,2000}\.[^,]{1,2000})|(({domain}[^\\,]{1,2000})\\{1,20})?({user}[^,]{1,2000})),""",
    """,({alert_severity}(?i)(low|medium|high|critical|informational)),""",
    """,THREAT,([^,]{0,2000},){20}(?:|({src_port}\d{1,100})),(?:|({dest_port}\d{1,100})),([^,]{0,2000},){3}(?:|({protocol}[^,]{1,2000})),(?:|({action}[^,]{0,2000})),""",
    """(?i),THREAT,(("[^"]{0,2000}?",)|([^,]{0,2000},)){30,31}(?i)(low|medium|high|critical|informational),({direction}[^,]{0,2000}),([^,]{1,2000},){3}({src_location}[^\d,]{1,2000})""",
    """,THREAT,(([^"]{1,2000}?"[^"]{1,2000}",)|([^,]{0,2000},){28})(({alert_name}[^,]{1,2000}?)\()?({alert_id}\d{1,100})?\)?,"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```