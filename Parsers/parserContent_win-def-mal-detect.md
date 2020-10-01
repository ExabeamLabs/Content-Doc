#### Parser Content
```Java
{
Name = win-def-mal-detect
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Windows Defender Antivirus""", """Detection Source:""", """Virus""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",    
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s+Name:\s*({alert_name}.*?)\s+ID:""",
    """\s+Category:\s*({alert_type}.*?)\s+Path:""",
    """\s+Severity:\s*({alert_severity}\w+?)\s+Category:""",
    """\s+User:\s*(({domain}[^\\=]+)\\+)?({user}.+?)\s+Process Name:""",
    """\s+Process Name:\s*({process}({directory}(?:[^,]+)?[\\\/])?({process_name}[^\\\/,]+?))\s+Signature Version:""",
    """\s+Action:\s*({outcome}.*?)\s+Action Status:""",
    """\s+Path:\s*(file:_)?({file_path}.*?)\s+Detection Origin:"""
  ]
  DupFields = ["directory->process_directory"]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName","alert_severity->sourceSeverity","alert_type->malwareCategory","file_path->malwareAttackerFile"]
    NameTemplate = """Windows Defender ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="user", Name="windows_id", Fields=["user->windows_id"]}
```