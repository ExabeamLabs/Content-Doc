#### Parser Content
```Java
{
Name = q-checkpoint-alert
  Vendor = Check Point Software
  Product = Check Point Endpoint Security
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "epoch" 
  Conditions = [ """__policy_id_tag:""", """;Protection""" ]
  Fields = [
    """date=({time}\d+);""",
    """exabeam_host=({host}[\w\-.]+)""",
    """;Protection (Name|name):\s*({alert_name}[^;]+);""",
    """;malware_action:\s*({alert_type}[^;]+);""",
    """;file name:\s*({malware_file_name}[^;]+);""",
    """;file_type:\s*({malware_file_type}[^;]+);""",
    """;severity:\s*({alert_severity}\d)""",
    """src:\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst:\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst_user_name:\s*[^(]+\(({user}[^)]+)""",
    """src_user_name:\s*[^(]+\(({user}[^)]+)""",
    """dst_user_name:\s*[^(]+\(({account}[^)]+).*src_user_name:\s*[^(]+\(({user}[^)]+)""",
    """;Protection Type:\s*({additional_info}[^;]+);""",
    """\Ws_port:\s*({src_port}\d+)""",
    """\Wservice:\s*({dest_port}\d+)""",
    """;Destination DNS Hostname:\s*({dest_host}[^;]+)""",
    """;src_machine_name:\s*({src_host}[^;]+)""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "malware_file_name->malwareAttackerFile", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Check Point Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```