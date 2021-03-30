#### Parser Content
```Java
{
Name = crowdstrike-file-process-alert
    Conditions = [ """"event_simpleName":"LsassHandleFromUnsignedModule"""" ]
    Fields = ${CrowdStrikeParserTemplates.crowdstrike-file-operations.Fields} [
      """"+aip"+:"+({src_ip}[A-za-z0-9.\d:]+)""",
      """"ConfigStateHash":"({old_hash}[^"]+)""",
      """"SHA256HashData":"({new_hash}[^"]+)""",
      """"ImageFileName":"({file_path}[^"]+)""",
      """"ImageFileName":"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+?\.({file_ext}[^\\\.\s"]+)?)"""",
      """"+event_simpleName"+:"+({alert_name}[^"]+)""",
      """"+id"+:"+({alert_id}[^"]+)""",
      """"+ContextProcessId"+:"+({process_guid}[^"]+)""",
      """"+TargetProcessId"+:"+({target_process_guid}[^"]+)"""
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