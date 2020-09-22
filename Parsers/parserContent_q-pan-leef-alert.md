#### Parser Content
```Java
{
Name = q-pan-leef-alert
  Vendor = Palo Alto Networks
  Product = WildFire
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss" 
  Conditions = ["LEEF:1.0|Palo Alto Networks", "cat=THREAT|subtype=wildfire" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_endTime=({time}\d{13})""",
    """subtype=({alert_type}wildfire)""",
    """Severity=({alert_severity}\d+)""",
    """Severity=({alert_severity}[^\|]+)\|""",
    """(URLCategory|Severity)=({alert_severity}benign|informational)"""
    """DestinationUser=(?:[^\\/]+[\\/])?({user}[^|]+)\|""",
    """\|src=({src_ip}[^|]+)\|dst=({dest_ip}[^|]+)\|""",
    """SessionID=({alert_id}[^|]+)\|""",
    """LEEF[^|]+?\|([^\|]+\|){3}({alert_name}[^|]+)\|""",
    """\|URLCategory=({category}.*?)\|""",
    """\|Miscellaneous="?({miscellaneous}[^\|"]+)"?\|"""
  ]
  DupFields = [ "miscellaneous->malware_url" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "category->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```