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
```