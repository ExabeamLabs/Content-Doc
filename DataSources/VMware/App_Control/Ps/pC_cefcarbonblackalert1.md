#### Parser Content
```Java
{
Name = cef-carbonblack-alert-1
  Vendor = VMware
  Product = App Control
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|Carbon Black|Carbon Black|""", """ cat=""", """ filePath=[""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[\w\-.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wcat=({alert_type}.+?)\s{0,100}(\w+=|$)""",
    """\WdeviceSeverity=({alert_severity}\d{1,100})""",
    """\Wdhost=({src_host}[\w\-.]{1,2000})""",
    """\WfilePath=\[({additional_info}[^\]]{1,2000}?)\]\s{0,100}(\w+=|$)""",
    """\WfilePath=.+?\\users\\+({user}[^\\\s]{1,2000})""",
    """\WfileHash=({md5}[^\s]{1,2000})""",
  ]
  SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "alert_type->description"]
      NameTemplate = """Carbon Black Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="src_address", Fields=["src_host->host_name"]

}
```