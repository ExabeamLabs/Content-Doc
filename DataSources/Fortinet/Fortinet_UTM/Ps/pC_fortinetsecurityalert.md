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
    """\Wdevname="{0,20}({host}[^\s"]{1,2000})"{0,20}(\s|")""",
    """\Wsrcip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdstip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wvirus="{0,20}({alert_name}.+?)["\s]{0,2000}(\w+=|$)""",
    """\Wdtype="{0,20}({alert_type}.+?)["\s]{0,2000}(\w+=|$)""",
    """\Wvirusid=({alert_id}\d{1,100})(\s|")""",
    """\Wurl="{0,20}({malware_url}[^"\s]{1,2000})""",
    """\Wref="{0,20}({additional_info}[^"\s]{1,2000})""",
    """\Wuser="{0,20}({user}[^"\s]{1,2000})""",
    """\Wcrlevel=({alert_severity}[^"\s]{1,2000})(\s|")""",
    """\Wsrcport=({src_port}\d{1,100})""",
    """\Wdstport=({dest_port}\d{1,100})""",
    """\Wservice="({protocol}[^"]{1,2000})"""",
    """\Wfilename="({malware_file_name}[^"]{1,2000})"""",
    """\Waction="({action}[^"]{1,2000})"""",

  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName","alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->description", "dest_ip->malwareAttackerIp", "malware_url->process_name"]
    NameTemplate = """Fortinet Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address"]

}
```