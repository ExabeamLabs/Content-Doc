#### Parser Content
```Java
{
Name = cef-carbonblack-alert-1
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|Carbon Black|Carbon Black|""", """ cat=""", """ filePath=[""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[\w\-.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """([^\|]*\|){5}({alert_name}[^\|]+)""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wcat=({alert_type}.+?)\s{0,100}(\w+=|$)""",
    """\WdeviceSeverity=({alert_severity}\d{1,100})""",
    """\Wdhost=({src_host}[\w\-.]+)""",
    """\WfilePath=\[({additional_info}[^\]]+?)\]\s{0,100}(\w+=|$)""",
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