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
    """date=({time}\d{1,100});""",
    """exabeam_host=({host}[\w\-.]+)""",
    """;Protection (Name|name):\s{0,100}({alert_name}[^;]+);""",
    """;malware_action:\s{0,100}({alert_type}[^;]+);""",
    """;file name:\s{0,100}({malware_file_name}[^;]+);""",
    """;file_type:\s{0,100}({malware_file_type}[^;]+);""",
    """;severity:\s{0,100}({alert_severity}\d)""",
    """src:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst_user_name:\s{0,100}[^(]+\(({user}[^)]+)""",
    """src_user_name:\s{0,100}[^(]+\(({user}[^)]+)""",
    """dst_user_name:\s{0,100}[^(]+\(({account}[^)]+).*src_user_name:\s{0,100}[^(]+\(({user}[^)]+)""",
    """;Protection Type:\s{0,100}({additional_info}[^;]+);""",
    """\Ws_port:\s{0,100}({src_port}\d{1,100})""",
    """\Wservice:\s{0,100}({dest_port}\d{1,100})""",
    """;Destination DNS Hostname:\s{0,100}({dest_host}[^;]+)""",
    """;src_machine_name:\s{0,100}({src_host}[^;]+)""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "malware_file_name->malwareAttackerFile", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Check Point Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```