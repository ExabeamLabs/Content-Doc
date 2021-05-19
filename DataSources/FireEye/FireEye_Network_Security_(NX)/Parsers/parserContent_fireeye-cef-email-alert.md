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
    """\|FireEye\|([^|]{0,2000}\|){3}({alert_type}[^|]{1,2000})""",
    """\|FireEye\|([^|]{0,2000}\|){4}({alert_severity}[^|]{1,2000})""",
    """\Wrt=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\WfilePath=({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrequest=({malware_url}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs5=({malware_url}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  	"""\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  	"""\Wsuser=({src_user}[^@\s]{1,2000})""",
  	"""\Wduser=({dest_user}[^@\s]{1,2000})""",
    """\Wduser=({user_email}[^@\s,]{1,2000}@[^@\s,]{1,2000})""",
    """\Wduser=({user}[^@\s,]{1,2000})""",
    """\Wcn2=({alert_id}\d{1,100})""",
    """\Wcs1=({alert_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsproc=({process_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wact=({action}[^=]{1,2000}?)\s{1,100}\w+="""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "malware_url->malwareAttackerUrl"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="url", Fields=["malware_url->url"]}
```