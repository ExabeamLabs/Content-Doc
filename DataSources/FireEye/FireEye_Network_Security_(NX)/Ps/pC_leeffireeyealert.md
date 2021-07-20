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
    """\WdevTime=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """\|FireEye\|CMS\|([^\|]{0,2000}\|){1}({alert_type}[^\|]{1,2000})""",
    """\Wsev=({alert_severity}\d{1,100})""",
    """\Wsname=({alert_name}[^\^]{1,2000})""",
    """\Wdvc=({host}[a-fA-F:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\WexternalId=({alert_id}\d{1,100})""",
    """\Wduser=({user_email}[^\^\s,]{1,2000})""",
    """\Wlink=({malware_url}[^\^]{1,2000})""",
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