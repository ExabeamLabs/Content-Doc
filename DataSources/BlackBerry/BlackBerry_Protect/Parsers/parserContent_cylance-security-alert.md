#### Parser Content
```Java
{
Name = cylance-security-alert
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """Event Type: ExploitAttempt""", """Process Name:""", ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d{1,100}Z \S+ CylancePROTECT""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """Event Type:\s{0,100}({alert_type}[^,]+)""",
    """Violation Type:\s{0,100}({alert_name}[^,]+)""",
    """Device Name:\s{0,100}({src_host}[\w\-.]+)""",
    """IP Address:\s{0,100}\(({src_ip}[a-fA-F:\d.]+)""",
    """Process Name:\s{0,100}({process}[^,]+\\({process_name}[^\\,]+))""",
    """User Name:\s{0,100}({user}[^,]+)""",
    """, Action: ({outcome}[^,]+?),"""
    """, Policy Name: ({additional_info}.+?)(\s{0,100}$|,)""" 
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost"]
    NameTemplate = """Cylance Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```