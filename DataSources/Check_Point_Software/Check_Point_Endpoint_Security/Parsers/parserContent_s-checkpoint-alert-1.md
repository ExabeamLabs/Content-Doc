#### Parser Content
```Java
{
Name = s-checkpoint-alert-1
  Vendor = Check Point Software
  Product = Check Point Endpoint Security
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """product=VPN-1 & FireWall-1""", """|malware_action=""" ]
  Fields = [
    """date=({time}\d{1,100})""",
    """exabeam_host=({host}[\w-.]+)""",
    """\|orig=({host}[^\|]+)\|""",
    """\|Protection name=({alert_name}[^\|]+)\|""",
    """\|malware_action=({alert_type}[^\|]+)\|""",
    """\|severity=({alert_severity}[^\|]+)\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|s_port=({src_port}\d{1,100})""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|service=({dest_port}\d{1,100})""",
    """\|action=({action}[^\|]+)""",
    """\|proto=({protocol}[^\|]+)""",
    """\|src_machine_name=({src_host}[^\|]+)""",
    """\|description=({additional_info}[^\|]+)""",
    """\|src_user_name=[^(]+\(({user}[^)]+)""",
    """\|user=[^(]+\(({user}[^)]+)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Check Point Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```