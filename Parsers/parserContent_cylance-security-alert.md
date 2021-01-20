#### Parser Content
```Java
{
Name = cylance-security-alert
  Vendor = Cylance
  Product = PROTECT
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """Event Type: ExploitAttempt""", """Process Name:""", ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d+Z \S+ CylancePROTECT""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """Event Type:\s*({alert_type}[^,]+)""",
    """Violation Type:\s*({alert_name}[^,]+)""",
    """Device Name:\s*({src_host}[\w\-.]+)""",
    """IP Address:\s*\(({src_ip}[a-fA-F:\d.]+)""",
    """Process Name:\s*({process}[^,]+\\({process_name}[^\\,]+))""",
    """User Name:\s*({user}[^,]+)""",
    """, Action: ({outcome}[^,]+?),"""
    """, Policy Name: ({additional_info}.+?)(\s*$|,)""" 
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost"]
    NameTemplate = """Cylance Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```