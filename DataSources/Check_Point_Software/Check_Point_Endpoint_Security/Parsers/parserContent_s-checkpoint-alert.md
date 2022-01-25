#### Parser Content
```Java
{
Name = s-checkpoint-alert
  Vendor = Check Point Software
  Product = Check Point Endpoint Security
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """|product=SmartDefense|""", """|action=drop|""" ]
  Fields = [
    """date=({time}\d{1,100});""",
    """exabeam_host=({host}[\w-.]{1,2000})""",
    """\|Protection Name=({alert_name}[^\|]{1,2000})\|""",
    """\|Attack Info=({alert_type}[^\|]{1,2000})\|""",
    """\|Severity=({alert_severity}[^\|]{1,2000})\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|s_port=({src_port}\d{1,100})""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|service=({dest_port}\d{1,100})""",
    """\|src_country=(?:Internal|({src_country}[^\|]{1,2000}))\|""",
    """\|dst_country=(?:Other|({dst_country}[^\|]{1,2000}))\|""",
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