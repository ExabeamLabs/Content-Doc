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
    """\sdvc="{1,20}({host}[^"]{1,2000})""",
    """\sdvchost="{1,20}({host}[^"]{1,2000})""",
    """\srt="{1,20}({time}\d{1,100})""",
    """\sduser="{1,20}({user}[^"@]{1,2000})""",
    """\sduser="{1,20}[^@"]{1,2000}@({domain}[^".]{1,2000})""",
    """\scat="{1,20}({alert_name}[^"/]{1,2000})""",
    """\sapp="{1,20}({alert_type}[^"]{1,2000})""",
    """0\|[^|]{1,2000}?\|Alert\|({alert_severity}\d{1,100})""",
    """\sdst="{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc="{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\srequest="{1,20}({additional_info}[^"]{1,2000})"""
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Skyfence Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```