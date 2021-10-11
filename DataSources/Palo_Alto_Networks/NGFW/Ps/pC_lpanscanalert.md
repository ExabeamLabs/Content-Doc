#### Parser Content
```Java
{
Name = l-pan-scan-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,scan,""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,([^,]{0,2000},){27}(("[^"]{0,2000}")|[^,]{0,2000}),([^,]{0,2000},){27}({host}[\w\-\.]{1,2000})(,|$)""",
    """:\d\d:\d\d\s{1,100}({host}[\w.-]{1,2000})\s""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]{0,2000},THREAT,({alert_type}[^,]{1,2000}),([^,]{0,2000},){2}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),""",
    """,THREAT,([^,]{0,2000},){9}(({domain}[^\\,]{1,2000})\\+)?({user}[^\\,]{1,2000})""",
    """,THREAT,([^,]{0,2000},){8}(({domain}[^\\,]{1,2000})\\+)?({user}[^\\,]{1,2000})""",
    """,THREAT,([^,]{0,2000},){27}"?({malware_url}[^,"]{1,2000})""",
    """,THREAT,([^,]{0,2000},){27}(("[^"]{0,2000}")|[^,]{0,2000}),({alert_name}[^,]{1,2000}),""",
    """,THREAT,([^,]{0,2000},){27}(("[^"]{0,2000}")|[^,]{0,2000}),([^,]{0,2000},){2}({alert_severity}[^,]{1,2000}),""",
    """,THREAT,([^,]{0,2000},){27}(("[^"]{0,2000}")|[^,]{0,2000}),([^,]{0,2000},){4}({alert_id}\d{1,100})""",
    """,THREAT,([^,]{0,2000},){20}(?:|({src_port}\d{1,100})),(?:|({dest_port}\d{1,100})),(?:[^,]{0,2000},){3}(?:|({protocol}[^,]{1,2000})),(?:|({action}[^,]{0,2000})),"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```