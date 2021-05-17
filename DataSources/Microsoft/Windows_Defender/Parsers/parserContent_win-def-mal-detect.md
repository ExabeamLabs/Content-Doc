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
    """exabeam_host=({host}[\w\-.]{1,2000})""",    
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s{1,100}Name:\s{0,100}({alert_name}.*?)\s{1,100}ID:""",
    """\s{1,100}Category:\s{0,100}({alert_type}.*?)\s{1,100}Path:""",
    """\s{1,100}Severity:\s{0,100}({alert_severity}\w+?)\s{1,100}Category:""",
    """\s{1,100}User:\s{0,100}(({domain}[^\\=]{1,2000})\\+)?({user}.+?)\s{1,100}Process Name:""",
    """\s{1,100}Process Name:\s{0,100}({process}({directory}(?:[^,]{1,2000})?[\\\/])?({process_name}[^\\\/,]{1,2000}?))\s{1,100}Signature Version:""",
    """\s{1,100}Action:\s{0,100}({outcome}.*?)\s{1,100}Action Status:""",
    """\s{1,100}Path:\s{0,100}(file:_)?({file_path}.*?)\s{1,100}Detection Origin:"""
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