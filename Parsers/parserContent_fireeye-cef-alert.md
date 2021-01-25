#### Parser Content
```Java
{
Name = fireeye-cef-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ "CEF:","""|FireEye|""", """ deviceSeverity=""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
    """\|FireEye\|.+?\|.+?\|.+?\|({alert_type}.+?)\|""",
    """\|FireEye\|.+?\|.+?\|.+?\|.+?\|({alert_severity}.+?)\|""",
    """\sdeviceSeverity=({alert_severity}\d+)""",
    """\sexternalId=({alert_id}[^\s]+)""",
    """\srt=({time}\d+)""",
    """\|FireEye\|.+?\|.+?\|.+?\|({alert_name}.+?)\|""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\scs1Label=sname cs1=({alert_name}.+?) """,
    """\scs1=({alert_name}.+?)\s+\w+=.*?cs1Label=sname""",
    """\scs5Label=cncHost cs5=({malware_url}.+?) """,
    """\srequest=({malware_url}.+?) """,
    """\sfname=({malware_url}.+?) """,
    """\sduser=<?({user}[^@]+)(@[^\s]+)?\s+\w+=""",
    """\ssuser=({additional_info}.+?)\s+\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdhost=({dest_host}[^\s]+)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```