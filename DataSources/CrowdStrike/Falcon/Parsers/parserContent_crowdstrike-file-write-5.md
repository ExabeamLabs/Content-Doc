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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"timestamp":\s{0,100}"({time}\d{1,100})""",
      """"event_simpleName":\s{0,100}"({event_code}[^"]+)""",
      """"aid":\s{0,100}"({aid}[^"]+)""",
      """"SourceFileName":\s{0,100}"({src_file_dir}[^"]+\\+)?({src_file_name}[^\\"]+)""",
      """"TargetFileName":\s{0,100}"({file_path}[^"]+)""",
      """"TargetFileName":\s{0,100}"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+\.({file_ext}[^\\\/"]+))""",
      """suser=(system|({user}[^\s]+))""",
      """src-account-name":"({account_name}[^"]+)""",
      """"((?i)SHA256String|SHA256HashData)":"({sha256}[^"]+)""""
    ]

```