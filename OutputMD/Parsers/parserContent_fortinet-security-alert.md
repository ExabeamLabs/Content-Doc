#### Parser Content
```Java
{
Name = fortinet-security-alert
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """subtype=""", """virus=""", """action=""" ]
  Fields = [ 
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time\=\d\d:\d\d:\d\d)""",
    """\Wdevname="*({host}[^\s"]+)"*(\s|")""",
    """\Wsrcip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdstip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wvirus="*({alert_name}.+?)["\s]*(\w+=|$)""",
    """\Wdtype="*({alert_type}.+?)["\s]*(\w+=|$)""",
    """\Wvirusid=({alert_id}\d+)(\s|")""",
    """\Wurl="*({malware_url}[^"\s]+)""",
    """\Wref="*({additional_info}[^"\s]+)""",
    """\Wuser="*({user}[^"\s]+)""",
    """\Wcrlevel=({alert_severity}[^"\s]+)(\s|")""",
    """\Wsrcport=({src_port}\d+)""",
    """\Wdstport=({dest_port}\d+)""",
    """\Wservice="({protocol}[^"]+)"""",
    """\Wfilename="({malware_file_name}[^"]+)"""",
    """\Waction="({action}[^"]+)"""",

  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName","alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->description", "dest_ip->malwareAttackerIp", "malware_url->process_name"]
    NameTemplate = """Fortinet Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```