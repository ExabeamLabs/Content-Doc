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
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """\|FireEye\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_type}[^|]{1,2000}?)\|""",
    """\|FireEye\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_severity}[^|]{1,2000}?)\|""",
    """\sdeviceSeverity=({alert_severity}\d{1,100})""",
    """\sexternalId=({alert_id}[^\s]{1,2000})""",
    """\srt=({time}\d{1,100})""",
    """\|FireEye\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_name}[^|]{1,2000}?)\|""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\scs1Label=sname cs1=({alert_name}.+?) """,
    """\scs1=({alert_name}.+?)\s{1,100}\w+=.*?cs1Label=sname""",
    """\scs5Label=cncHost cs5=({malware_url}.+?) """,
    """\srequest=({malware_url}.+?) """,
    """\sfname=({malware_url}.+?) """,
    """\sduser=<?({user}[^@]{1,2000})(@[^\s]{1,2000})?\s{1,100}\w+=""",
    """\ssuser=({additional_info}.+?)\s{1,100}\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """proto=({protocol}[^\s]{1,2000})""",
    """smac=({src_mac}[^\s]{1,2000})""",
    """dmac=({dest_mac}[^\s]{1,2000})""",
    """spt=({src_port}\d{1,100})""",
    """fileHash=({file_hash}[^\s]{1,2000})""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```