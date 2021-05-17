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
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000})\s{1,100}Product=""",
    """\sPolicy="({alert_name}[^"]{1,2000})"""",
    """\sProtocol="({alert_type}[^"]{1,2000})"""",
    """\sSeverity="({alert_severity}[^"]{1,2000})"""",
    """\sSrcIP="({src_ip}[^"]{1,2000})"""",
    """\sSrcPort="({src_port}[^"]{1,2000})"""",
    """\sDestIP="({dest_ip}[^"]{1,2000})"""",
    """\sDestPort="({dest_port}[^"]{1,2000})"""",
    """\sMessage="({additional_info}.+?)"\s{1,100}MD5="""",
    """\sTarget="(?:(<n\/a>)|({malware_url}[^"]{1,2000}))"""",
    """\sMalware="(?:(<n\/a> <n\/a>)|({malware_url}[^"]{1,2000}))"""",
    """\sSubject="(?:(<n\/a>)|({malware_url}[^"]{1,2000}))""""
    """\sFilename="(?:(<n\/a>)|({malware_url}[^"]{1,2000}))""""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "malware_url->malwareAttackerFile", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Fidelis Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```