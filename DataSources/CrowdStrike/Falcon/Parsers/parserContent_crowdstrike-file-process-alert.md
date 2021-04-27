#### Parser Content
```Java
{
Name = crowdstrike-file-process-alert
    Conditions = [ """"event_simpleName":""", """"LsassHandleFromUnsignedModule"""" ]
    Fields = ${CrowdStrikeParserTemplates.crowdstrike-file-operations.Fields} [
      """"+aip"+:\s*"+({src_ip}[A-za-z0-9.\d:]+)""",
      """"ConfigStateHash":\s*"({old_hash}[^"]+)""",
      """"SHA256HashData":\s*"({new_hash}[^"]+)""",
      """"ImageFileName":\s*"({file_path}[^"]+)""",
      """"ImageFileName":\s*"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+?\.({file_ext}[^\\\.\s"]+)?)"""",
      """"ImageFileName\\*":\\*"({process}[^"]+\\({process_name}[^"\\]+))""",
      """"+event_simpleName"+:\s*"+({alert_name}[^"]+)""",
      """"+id"+:\s*"+({alert_id}[^"]+)""",
      """"+ContextProcessId"+:\s*"+({process_guid}[^"]+)""",
      """"+TargetProcessId"+:\s*"+({target_process_guid}[^"]+)"""
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
      """src-account-name":"({account_name}[^"]+)"""
    ]

```