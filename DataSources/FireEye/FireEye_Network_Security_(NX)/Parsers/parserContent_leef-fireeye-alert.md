#### Parser Content
```Java
{
Name = leef-fireeye-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|FireEye|CMS|""", """dvchost=""", """action=""" ]
  Fields = [
    """\WdevTime=({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\|FireEye\|CMS\|([^\|]*\|){1}({alert_type}[^\|]+)""",
    """\Wsev=({alert_severity}\d+)""",
    """\Wsname=({alert_name}[^\^]+)""",
    """\Wdvc=({host}[a-fA-F:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\WexternalId=({alert_id}\d+)""",
    """\Wduser=({user_email}[^\^\s,]+)""",
    """\Wlink=({malware_url}[^\^]+)""",
  ]
  DupFields = [ "user_email->user" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "malware_url->malwareAttackerUrl"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="url", Fields=["malware_url->url"]}
```