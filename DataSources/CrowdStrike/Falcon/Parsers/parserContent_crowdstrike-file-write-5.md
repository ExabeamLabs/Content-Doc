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
```