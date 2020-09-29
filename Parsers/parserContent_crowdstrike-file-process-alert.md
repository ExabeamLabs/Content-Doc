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
```