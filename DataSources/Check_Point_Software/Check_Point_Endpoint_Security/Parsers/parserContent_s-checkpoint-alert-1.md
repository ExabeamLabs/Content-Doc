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
    """exabeam_host=({host}[\w-.]{1,2000})""",
    """\|orig=({host}[^\|]{1,2000})\|""",
    """\|Protection name=({alert_name}[^\|]{1,2000})\|""",
    """\|malware_action=({alert_type}[^\|]{1,2000})\|""",
    """\|severity=({alert_severity}[^\|]{1,2000})\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|s_port=({src_port}\d{1,100})""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|service=({dest_port}\d{1,100})""",
    """\|action=({action}[^\|]{1,2000})""",
    """\|proto=({protocol}[^\|]{1,2000})""",
    """\|src_machine_name=({src_host}[^\|]{1,2000})""",
    """\|description=({additional_info}[^\|]{1,2000})""",
    """\|src_user_name=[^(]{1,2000}\(({user}[^)]{1,2000})""",
    """\|user=[^(]{1,2000}\(({user}[^)]{1,2000})"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Check Point Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```