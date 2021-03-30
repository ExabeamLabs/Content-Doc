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
      """"timestamp":\s*"({time}\d+)""",
      """"event_simpleName":\s*"({event_code}[^"]+)""",
      """"aid":\s*"({aid}[^"]+)""",
      """"SourceFileName":\s*"({src_file_dir}[^"]+\\+)?({src_file_name}[^\\"]+)""",
      """"TargetFileName":\s*"({file_path}[^"]+)""",
      """"TargetFileName":\s*"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+\.({file_ext}[^\\\/"]+))""",
      """suser=(system|({user}[^\s]+))""",
      """src-account-name":"({account_name}[^"]+)""",
      """"((?i)SHA256String|SHA256HashData)":"({sha256}[^"]+)""""
    ]

```