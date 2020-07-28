#### Parser Content
```Java
{
Name = s-skyfence-alert
  Vendor = Forcepoint
  Product = Forcepoint CASB
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ "CEF", "Skyfence", """|Alert|""" ]
  Fields = [
    """\sdvc="+({host}[^"]+)""",
    """\sdvchost="+({host}[^"]+)""",
    """\srt="+({time}\d+)""",
    """\sduser="+({user}[^"@]+)""",
    """\sduser="+[^@"]+@({domain}[^".]+)""",
    """\scat="+({alert_name}[^"/]+)""",
    """\sapp="+({alert_type}[^"]+)""",
    """0\|.+?\|Alert\|({alert_severity}\d+)""",
    """\sdst="+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc="+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\srequest="+({additional_info}[^"]+)"""
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Skyfence Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```