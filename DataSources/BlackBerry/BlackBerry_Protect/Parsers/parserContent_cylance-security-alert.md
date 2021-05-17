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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """Event Type:\s{0,100}({alert_type}[^,]{1,2000})""",
    """Violation Type:\s{0,100}({alert_name}[^,]{1,2000})""",
    """Device Name:\s{0,100}({src_host}[\w\-.]{1,2000})""",
    """IP Address:\s{0,100}\(({src_ip}[a-fA-F:\d.]{1,2000})""",
    """Process Name:\s{0,100}({process}[^,]{1,2000}\\({process_name}[^\\,]{1,2000}))""",
    """User Name:\s{0,100}({user}[^,]{1,2000})""",
    """, Action: ({outcome}[^,]{1,2000}?),"""
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