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
    """\sdvchost=({host}[\w\-.]+)""",
    """\srt=({time}\d+)\s+(\w+=|$)""",
    """\scat=({alert_name}[^=]+)\s+(\w+=|$)""",
    """\sshost=({src_host}[^=]+)\s+(\w+=|$)""",
    """\sdhost=({dest_host}[^=]+)\s+(\w+=|$)""",
    """\ssrc=({src_ip}[A-Fa-f\d:.]+)\s+(\w+=|$)""",
    """\sdst=({dest_ip}[A-Fa-f\d:.]+)\s+(\w+=|$)""",
    """\sdeviceSeverity=({alert_severity}\d+)\s""",
    """\|spyware\|THREAT\|(Unknown|({alert_severity}[^\|]+))""",
    """\seventId=({alert_id}\d+)\s+(\w+=|$)""",
    """\sapp=({threat_category}[^=]+)\s+(\w+=|$)""",
    """\ssuser=((({domain}[^\\\/=]+)[\\\/]+)?({user}[^\s]+))"""
  ]
  DupFields = [ "alert_name->alert_type" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```