#### Parser Content
```Java
{
Name = pan-flood-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,flood,""" ]
  Fields = [
    """\s+({host}[^\s]+)\s+\d+,.+?,.+?,THREAT,""",
    """exabeam_host=({host}[^\s]+)""",
    """\s({host}[^\s]+?) \d+,\d+/\d+/\d+\s+\d\d:\d\d:\d\d,"""
    """THREAT,[^,]+,\d+,({time}\d+/\d+/\d+\s+\d\d:\d\d:\d\d),({src_ip}[^,]*?),({dest_ip}[^,]*?),([^,]*?,){21}({alert_type}[^,]*),\"*({malware_url}[^",]+)?\"*,(.+?),.+?,({alert_severity}.+?),({additional_info}[^,]+),({alert_id}\d+)""",
    """,THREAT,([^,]*,){28}({alert_name}[^,]+),"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address"]}
```