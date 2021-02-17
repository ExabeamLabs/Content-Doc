#### Parser Content
```Java
{
Name = cef-fireeye-hx-security-alert
  Vendor = FireEye
  Product = FireEye Endpoint Security (HX)
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|fireeye|hx|""", """|Malware Hit Found|""", """ categoryTupleDescription=""", """ cs11=""" ]
  Fields = [
    """\Wrt=({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """CEF:([^\|]*\|){6}({alert_severity}\d+)""",
    """\Wdst=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdhost=({src_host}[\w\-.]+)""",
    """\Wdntdom=({domain}[^\s]+)""",
    """\WexternalId=({alert_id}\d+)""",
    """\Wact=({alert_type}.+?)\s*(\w+=|$)""",
    """\Wcs4=({process}.+?)\s*(\w+=|$)""",
    """\Wcs4=({directory}[^\.]+?)\\+({process_name}[^\\]+?)\s*(\w+=|$)""",
    """\Wcs9=({md5}\S+)""",
    """\Wcs11=({alert_name}.+?)\s*(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s*(\w+=|$)"""
  ]
  DupFields = ["directory->process_directory"]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```