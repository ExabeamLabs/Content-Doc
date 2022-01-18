#### Parser Content
```Java
{
Name = cef-palo-alto-networks-security-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|Palo Alto Networks|PAN-OS|""", """|spyware|THREAT|""" ]
  Fields = [
    """\sdvchost=({host}[\w\-.]{1,2000})""",
    """\srt=({time}\d{1,100})\s{1,100}(\w+=|$)""",
    """\scat=({alert_name}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """\sshost=({src_host}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """\sdhost=({dest_host}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """\ssrc=({src_ip}[A-Fa-f\d:.]{1,2000})\s{1,100}(\w+=|$)""",
    """\sdst=({dest_ip}[A-Fa-f\d:.]{1,2000})\s{1,100}(\w+=|$)""",
    """\sdeviceSeverity=({alert_severity}\d{1,100})\s""",
    """\|spyware\|THREAT\|(Unknown|({alert_severity}[^\|]{1,2000}))""",
    """\seventId=({alert_id}\d{1,100})\s{1,100}(\w+=|$)""",
    """\sapp=({threat_category}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """\ssuser=((({domain}[^\\\/=]{1,2000})[\\\/]{1,2000})?({user}[^\s]{1,2000}))"""
  ]
  DupFields = [ "alert_name->alert_type" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```