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
    """\sdvc="{1,20}({host}[^"]+)""",
    """\sdvchost="{1,20}({host}[^"]+)""",
    """\srt="{1,20}({time}\d{1,100})""",
    """\sduser="{1,20}({user}[^"@]+)""",
    """\sduser="{1,20}[^@"]+@({domain}[^".]+)""",
    """\scat="{1,20}({alert_name}[^"/]+)""",
    """\sapp="{1,20}({alert_type}[^"]+)""",
    """0\|[^|]+?\|Alert\|({alert_severity}\d{1,100})""",
    """\sdst="{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc="{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\srequest="{1,20}({additional_info}[^"]+)"""
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Skyfence Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```