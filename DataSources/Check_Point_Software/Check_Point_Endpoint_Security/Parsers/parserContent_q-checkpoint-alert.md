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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """;Protection (Name|name):\s{0,100}({alert_name}[^;]{1,2000});""",
    """;malware_action:\s{0,100}({alert_type}[^;]{1,2000});""",
    """;file name:\s{0,100}({malware_file_name}[^;]{1,2000});""",
    """;file_type:\s{0,100}({malware_file_type}[^;]{1,2000});""",
    """;severity:\s{0,100}({alert_severity}\d)""",
    """src:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst_user_name:\s{0,100}[^(]{1,2000}\(({user}[^)]{1,2000})""",
    """src_user_name:\s{0,100}[^(]{1,2000}\(({user}[^)]{1,2000})""",
    """dst_user_name:\s{0,100}[^(]{1,2000}\(({account}[^)]{1,2000}).*src_user_name:\s{0,100}[^(]{1,2000}\(({user}[^)]{1,2000})""",
    """;Protection Type:\s{0,100}({additional_info}[^;]{1,2000});""",
    """\Ws_port:\s{0,100}({src_port}\d{1,100})""",
    """\Wservice:\s{0,100}({dest_port}\d{1,100})""",
    """;Destination DNS Hostname:\s{0,100}({dest_host}[^;]{1,2000})""",
    """;src_machine_name:\s{0,100}({src_host}[^;]{1,2000})""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "malware_file_name->malwareAttackerFile", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Check Point Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```