#### Parser Content
```Java
{
Name = s-checkpoint-alert-2
  Vendor = Check Point Software
  Product = Check Point Endpoint Security
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """product=Threat Emulation""", """|malware_action=""" ]
  Fields = [
    """time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w-.]+)""",
    """\|orig=({host}[^\|]+)\|""",
    """\|Protection Name=({alert_name}[^\|]+)\|""",
    """Malware signature matched \(\s{0,100}({alert_name}.+?)\s{0,100}\)""",
    """\|Protection Type=({alert_type}[^\|]+)\|""",
    """\|severity=({alert_severity}[^\|]+)\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|s_port=({src_port}\d{1,100})""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|service=({dest_port}\d{1,100})""",
    """\|action=({action}[^\|]+)""",
    """\|proto=({protocol}[^\|]+)""",
    """\|file_md5=({md5}[^\|]+)""",
    """\|malware_action=({additional_info}[^\|]+)""",
    """\|action=({action}[^\|]+)"""
    """\|file_name=({file_name}[^\|]+)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Check Point Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```