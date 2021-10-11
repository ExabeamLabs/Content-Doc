#### Parser Content
```Java
{
Name = s-panngwf-spyware-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,spyware,""" ]
  Fields = [ 
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"host":\{.*?"name":"({host}[^"]{1,2000})".*?\}""",
    """,THREAT,spyware,[^,]{1,2000},({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """,THREAT,spyware,[^,]{1,2000},({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,THREAT,spyware,([^,]{1,2000},){2}({src_ip}[a-fA-F\d:.]{1,2000}),({dest_ip}[a-fA-F\d:.]{1,2000}),""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s\d{1,100}""",
    """THREAT,({alert_type}\w+),""",
    """({alert_name}spyware)""",
    """,THREAT,[^"]{1,2000}?,({action}[^,]{1,2000}),\\?"[^"]{0,2000}"""",
    """,THREAT,.+?,\\?"{1,20}([^\(]{1,2000}\()?(|({malware_url}[^"\)]{1,2000}?))\)?[\\\/]{0,2000}"{1,20},""",
    """,THREAT,([^,]{0,2000},){28}\d{0,2000}(|({alert_name}[^\(,:]{1,2000}))(:[^\(]{1,2000})?\(({alert_id}\d{1,100})?""",
    """,THREAT,[^"]{1,2000}?,\\?"[^\s]{0,2000}?"{1,20},?\d{0,2000}(|({alert_name}[^,\("]{1,2000}?))\s{0,100}\(({alert_id}\d{1,100})?""",
    """,THREAT,[^"]{1,2000}?,\\?"[^\s]{0,2000}",[^,]{0,2000},({category}[^,]{1,2000}),""",
    """THREAT,spyware,([^,]{0,2000},){29}({alert_severity}\w+)""",
    """THREAT,spyware,[^"]{1,2000}?,\\?"[^\s]{0,2000}?",([^,]{0,2000},){2}({alert_severity}\w+)""",
    """THREAT,spyware,([^,]{0,2000},){7}(({user_email}[^@,]{1,2000}@[^\.,]{1,2000}\.[^,]{1,2000})|(({domain}[^\\\/,]{1,2000})[\\\/]{1,2000})?({user}[^\\\/,]{1,2000})),""",
    """THREAT,spyware,([^,]{0,2000},){19}(?:|({src_port}\d{1,100})),(?:|({dest_port}\d{1,100})),([^,]{0,2000},){3}(?:|({protocol}[^,]{1,2000})),(?:|({action}[^,]{1,2000})),\\?"{0,20}""",
    """THREAT,spyware,([^,]{0,2000},){9}({app}[^,]{1,2000}),""",
    """,THREAT,[^"]{1,2000}?,\\?"[^\s]{0,2000}?"{1,20},?([^"]{1,2000})"{1,20},({alert_id}\d{1,100})?""",
    """(?i),THREAT,(("[^"]{0,2000}?",)|([^,]{0,2000},)){30,31}(?i)(low|medium|high|critical|informational),({direction}[^,]{0,2000}),([^,]{1,2000},){3}({src_location}[^\d,]{1,2000})""",
    """,THREAT,[^"]{1,2000}?,\\?"[^\s]{0,2000}?"{1,20},\d{0,2000}(|({alert_name}[^,\("]{1,2000}?)\(({alert_id}\d{1,100})?\)),(|({category}[^,]{0,2000})),(|({alert_severity}[^,]{0,100})),""",
    """,(?i)(low|medium|high|critical|informational),({direction}[^,]{0,2000}),([^,]{1,2000},){3}({src_location}[^\d,]{1,2000})""",
    """THREAT,spyware,(("[^\s]{1,2000}"|[^,]{0,2000}),){64}({threat_category}[^,]{1,2000}),""",
    """,THREAT,([^,]{0,2000},){27}(\\?"({malware_url}[^<>]{1,2000}?)[\\\/]{0,20}"|[^,]{0,2000}),(|({alert_name}[^,\("]{1,2000}?)\(({alert_id}\d{1,100})?\)),(|({category}[^,]{0,2000})),(|({alert_severity}\w+)),("[^"]{0,2000}",|[^,]{0,2000},){34}(|({threat_category}[^,]{1,2000})),"""
  ]
  DupFields = ["action->outcome"] 
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->description", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```