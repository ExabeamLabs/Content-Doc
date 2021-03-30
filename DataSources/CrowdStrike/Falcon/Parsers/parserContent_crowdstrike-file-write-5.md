#### Parser Content
```Java
{
Name = crowdstrike-file-write-5
    Conditions = [ """"event_simpleName":"FsVolumeMounted"""" ]
    Fields = ${CrowdStrikeParserTemplates.crowdstrike-file-operations.Fields} [
    """"VolumeName":"({file_path}[^"]+)""",
    """"VolumeName":"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+(\.({file_ext}[^\\\/"]+))?)""",
    ]
  }
crowdstrike-file-operations = {
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "epoch"
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """({host}[\w\-.]+)\s+Skyformation""",
      """"timestamp":"({time}\d+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"SourceFileName":"({src_file_dir}[^"]+\\+)?({src_file_name}[^\\"]+)""",
      """"TargetFileName":"({file_path}[^"]+)""",
      """"TargetFileName":"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+\.({file_ext}[^\\\/"]+))""",
      """suser=(system|({user}[^\s]+))"""
    ]

```