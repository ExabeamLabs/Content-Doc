#### Parser Content
```Java
{
Name = crowdstrike-file-write-1
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":""", """"DirectoryCreate"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """({host}[\w\-.]+)\s+Skyformation""",
      """"timestamp":\s*"({time}\d+)""",
      """"event_simpleName":\s*"({event_code}[^"]+)""",
      """"aid":\s*"({aid}[^"]+)""",
      """"TargetFileName":\s*"({file_path}[^"]+)""",
      """"TargetFileName":\s*"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+)""",
      """({file_type}Directory)""",
      """suser=(system|({user}[^\s]+))"""
    ]
  }
```