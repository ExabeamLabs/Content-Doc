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
    """\s{1,100}({host}[^\s]{1,2000})\s{1,100}\d{1,100},.+?,.+?,THREAT,""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\s({host}[^\s]{1,2000}?) \d{1,100},\d{1,100}/\d{1,100}/\d{1,100}\s{1,100}\d\d:\d\d:\d\d,""",
    """THREAT,[^,]{1,2000},\d{1,100},({time}\d{1,100}/\d{1,100}/\d{1,100}\s{1,100}\d\d:\d\d:\d\d),({src_ip}[^,]{0,2000}?),({dest_ip}[^,]{0,2000}?),([^,]{0,2000}?,){21}({alert_type}[^,]{0,2000}),\"{0,20}({malware_url}[^",]{1,2000})?\"{0,20},([^,]{1,2000}?),[^,]{1,2000}?,({alert_severity}[^,]{1,2000}?),({additional_info}[^,]{1,2000}),({alert_id}\d{1,100})""",
    """,THREAT,([^,]{0,2000},){28}({alert_name}[^,]{1,2000}),"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address"]}
```