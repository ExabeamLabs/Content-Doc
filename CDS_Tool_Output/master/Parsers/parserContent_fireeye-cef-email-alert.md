#### Parser Content
```Java
{
Name = fireeye-cef-email-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Conditions = [ "CEF:","""|FireEye|eMPS""", """suser=""" ]
  Fields = [
    """\|FireEye\|([^|]*\|){3}({alert_type}[^|]+)""",
    """\|FireEye\|([^|]*\|){4}({alert_severity}[^|]+)""",
    """\Wrt=({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\WfilePath=({additional_info}.+?)(\s+\w+=|\s*$)""",
    """\Wrequest=({malware_url}.+?)(\s+\w+=|\s*$)""",
    """\Wcs5=({malware_url}.+?)(\s+\w+=|\s*$)""",
  	"""\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
  	"""\Wsuser=({src_user}[^@\s]+)""",
  	"""\Wduser=({dst_user}[^@\s]+)""",
    """\Wduser=({user_email}[^@\s,]+@[^@\s,]+)""",
    """\Wduser=({user}[^@\s,]+)""",
    """\Wcn2=({alert_id}\d+)""",
    """\Wcs1=({alert_name}.+?)(\s+\w+=|\s*$)""",
    """\Wsproc=({process_name}.+?)(\s+\w+=|\s*$)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "malware_url->malwareAttackerUrl"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="url", Fields=["malware_url->url"]}
```