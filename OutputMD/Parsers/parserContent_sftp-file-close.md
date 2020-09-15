#### Parser Content
```Java
{
Name = sftp-file-close
  DataType = "file-operations"
  Conditions = [ """sftp-server[""",""" close """]
  Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
    """({activity}close) "+({file_path}({file_parent}[^"]*?[\\\/]+)?\s*({file_name}[^"\\\/]*?(\.({file_ext}\w+))?))"+""",
    """written ({bytes}\d+)"""
	]
  }
```