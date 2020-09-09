#### Parser Content
```Java
{
Name = cef-sourcefire-estreamer-alert
  Vendor = Cisco
  Product = Cisco Firepower  
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""","""|Sourcefire|Sourcefire Management Console eStreamer|""" ]
  Fields = [
      """\srt=({time}\d+)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdhost=({src_host}[^\s]+)""",
      """\sshost=({dest_host}[^\s]+)""",
      """\sdst=(?:0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
      """\ssrc=(?:0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
      """\scategory=({additional_info}.+?)\s+(\w+=|$)""",
      """\sduser=({user}.+?)\s+(\w+=|$)""",
      """\sexternalId=({alert_id}\d+)""",
      """\|Sourcefire\|[^|]*\|[^|]*\|[^|]*\|[^-|]+\-[^\s]+\s+({alert_name}[^|]+)\|""",
      """\|Sourcefire\|[^|]*\|[^|]*\|[^|]*\|({alert_type}[^-|]+\-[^\s]+)[^|]+\|""",
      """\|Sourcefire\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|({alert_severity}[^|]+)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "dest_ip->malwareAttackerIp", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Cisco Sourcefire Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```