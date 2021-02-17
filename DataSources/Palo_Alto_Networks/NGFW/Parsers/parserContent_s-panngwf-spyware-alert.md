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
    """exabeam_host=({host}[^\s]+)""",
    """"host":\{.*?"name":"({host}[^"]+)".*?\}""",
    """,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),""",
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s""",
    """THREAT,({alert_type}\w+),""",
    """,THREAT,[^"]+?,({action}[^,]+),\\?"[^"]*"""",
    """,THREAT,.+?,\\?"+([^\(]+\()?(|({malware_url}[^"\)]+?))\)?\\?"+,""",
    """,THREAT,[^"]+?,\\?"[^\s]*?"+,?({alert_name}[^,\("]+)\s+\(({alert_id}\d+)?""",
    """,THREAT,[^"]+?,\\?"[^\s]*?",[^,]*,({threat_category}[^,]+),""",
    """THREAT,spyware,([^,]*,){29}({alert_severity}\w+)""",
    """THREAT,spyware,[^"]+?,\\?"[^\s]*?",([^,]*,){2}({alert_severity}\w+)""",
    """THREAT,spyware,([^,]*,){7}(({domain}[^\\\/,]+)[\\\/]+)?({user}[^\\\/,]+),""",
    """THREAT,spyware,([^,]*,){19}(?:|({src_port}\d+)),(?:|({dest_port}\d+)),([^,]*,){3}(?:|({protocol}[^,]+)),(?:|({action}[^,]+)),\\?"""",
    """THREAT,spyware,([^,]*,){9}({app}[^,]+),""",
    """,THREAT,[^"]+?,\\?"[^\s]*?"+,?([^"]+)"+,({alert_id}\d+)?"""
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