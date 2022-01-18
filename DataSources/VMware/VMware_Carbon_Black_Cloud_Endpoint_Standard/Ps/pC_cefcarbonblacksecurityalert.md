#### Parser Content
```Java
{
Name = cef-carbonblack-security-alert
  Vendor = VMware
  Product = VMware Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|CarbonBlack|CbDefense_Syslog_Connector|""", """|Active_Threat|""" ]
  Fields = [
    """(\s|\|)rt="({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """(\s|\|)dvc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """(\s|\|)dvchost=({host}[\w\-.]{1,2000})""",
    """(\s|\|)duser=({user}[^\s]{1,2000})""",
    """([^\|]{0,2000}\|){5}({alert_type}[^\|]{1,2000})""",
    """([^\|]{0,2000}\|){6}({alert_name}[^\|]{1,2000})""",
    """([^\|]{0,2000}\|){7}({alert_severity}\d{1,100})""",
    """(\s|\|)cs4="({alert_id}[^"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address"]

}
```