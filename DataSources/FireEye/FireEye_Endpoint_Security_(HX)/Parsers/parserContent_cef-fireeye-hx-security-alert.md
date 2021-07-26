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
    """\Wrt=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}\d{1,100})""",
    """\Wdst=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdhost=({src_host}[\w\-.]{1,2000})""",
    """\Wdntdom=({domain}[^\s]{1,2000})""",
    """\WexternalId=({alert_id}\d{1,100})""",
    """\Wact=({alert_type}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs4=({process}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs4=({directory}[^\.]{1,2000}?)\\+({process_name}[^\\]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\Wcs9=({md5}\S+)""",
    """\Wcs11=({alert_name}.+?)\s{0,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s{0,100}(\w+=|$)"""
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