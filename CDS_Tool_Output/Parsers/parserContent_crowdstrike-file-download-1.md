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
```