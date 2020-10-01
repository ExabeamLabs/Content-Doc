#### Parser Content
```Java
{
Name = s-fidelis-alert
  Vendor = Fidelis
  Product = Fidelis Network
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Product="Fidelis network"""", """AlertId=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]+)\s+Product=""",
    """\sPolicy="({alert_name}[^"]+)"""",
    """\sProtocol="({alert_type}[^"]+)"""",
    """\sSeverity="({alert_severity}[^"]+)"""",
    """\sSrcIP="({src_ip}[^"]+)"""",
    """\sSrcPort="({src_port}[^"]+)"""",
    """\sDestIP="({dest_ip}[^"]+)"""",
    """\sDestPort="({dest_port}[^"]+)"""",
    """\sMessage="({additional_info}.+?)"\s+MD5="""",
    """\sTarget="(?:(<n\/a>)|({malware_url}[^"]+))"""",
    """\sMalware="(?:(<n\/a> <n\/a>)|({malware_url}[^"]+))"""",
    """\sSubject="(?:(<n\/a>)|({malware_url}[^"]+))""""
    """\sFilename="(?:(<n\/a>)|({malware_url}[^"]+))""""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "malware_url->malwareAttackerFile", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Fidelis Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```