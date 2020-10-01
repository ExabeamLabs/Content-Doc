#### Parser Content
```Java
{
Name = cef-carbonblack-alert-1
  Vendor = Carbon Black
  Product = CB Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|Carbon Black|Carbon Black|""", """ cat=""", """ filePath=[""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[\w\-.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """([^\|]*\|){5}({alert_name}[^\|]+)""",
    """\WeventId=({alert_id}\d+)""",
    """\Wcat=({alert_type}.+?)\s*(\w+=|$)""",
    """\WdeviceSeverity=({alert_severity}\d+)""",
    """\Wdhost=({src_host}[\w\-.]+)""",
    """\WfilePath=\[({additional_info}[^\]]+?)\]\s*(\w+=|$)""",
    """\WfilePath=.+?\\users\\+({user}[^\\\s]+)""",
    """\WfileHash=({md5}[^\s]+)""",
  ]
  SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "alert_type->description"]
      NameTemplate = """Carbon Black Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```