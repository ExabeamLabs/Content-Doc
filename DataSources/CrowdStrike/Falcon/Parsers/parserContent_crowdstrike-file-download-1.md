#### Parser Content
```Java
{
Name = crowdstrike-file-download-1
    Conditions = [ """"event_simpleName":"LFODownloadConfirmation"""" ]
    Fields = ${CrowdStrikeParserTemplates.crowdstrike-file-operations.Fields} [
      """"+aip"+:"+({src_ip}[A-za-z0-9.\d:]+)""",
      """DownloadPath"+:"+({file_path}[^"]+)""",
      """DownloadPort"+:"+({dest_port}[^"]+)""",
      """DownloadServer"+:"+({dest_host}[^"]+)""",
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