#### Parser Content
```Java
{
Name = crowdstrike-file-write-6
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"CriticalFileModified"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """({host}[\w\-.]+)\s+Skyformation""",
      """"timestamp":"({time}\d+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"TargetFileName":"({file_path}[^"]+)""",
      """"TargetFileName":"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+)""",
      """({accesses}Modified)"""
    ]
  }
```