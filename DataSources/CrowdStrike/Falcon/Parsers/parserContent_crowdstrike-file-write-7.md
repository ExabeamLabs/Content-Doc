#### Parser Content
```Java
{
Name = crowdstrike-file-write-7
    Conditions = [ """"event_simpleName":"FsVolumeUnmounted"""" ]
    Fields = ${CrowdStrikeParserTemplates.crowdstrike-file-operations.Fields} [
       """"VolumeName":"({file_path}[^"]+)""",
       """VolumeMountPoint"+:"+\/*({device_id}[^"]+)"""
       """"VolumeName":"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+(\.({file_ext}[^\\\/"]+))?)""",
       """"ConfigStateHash":"({old_hash}[^"]+)""",
       """"SHA256HashData":"({new_hash}[^"]+)""",
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