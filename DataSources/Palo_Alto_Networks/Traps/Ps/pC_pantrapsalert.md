#### Parser Content
```Java
{
Name = pan-traps-alert
  Vendor = Palo Alto Networks
  Product = Traps
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """,Traps Agent,""", """Prevention Key:""" ]
  Fields = [
    """\d{1,100}\s{1,100}\d{4}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z(\-|\+)\d{1,100}:\d{1,100}\s{1,100}({host}(\d{1,3}\.){3}\d{1,3})""",
    """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d),Traps Agent,""",
    """,Traps Agent,([^,]{0,2000},){2}(?:-|({alert_name}[^,]{1,2000})),(?:-|({src_host}[^,]{1,2000})),(({domain}[^\\]{1,2000})\\)?(?:-|({user}[^,]{1,2000})),(|({additional_info}.+?))\s{0,100}Prevention Key:""",
    """Prevention Key:\s{0,100}({alert_id}[^,\s]{1,2000}),(?:-|({alert_severity}\d{1,100})),(?:-|({alert_type}[^,]{1,2000})),(?:-|({malware_url}[^,]{1,2000})),([^,]{0,2000},){2}(?:-|({dest_ip}(\d{1,3}\.){3}\d{1,3}))""",
    """Parent process:\s{0,100}({process_name}[^\.]{1,2000})""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```