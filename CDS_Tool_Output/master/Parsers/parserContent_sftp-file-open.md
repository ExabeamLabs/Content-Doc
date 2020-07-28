#### Parser Content
```Java
{
Name = sftp-file-open
  DataType = "file-operations"
  Conditions = [ """sftp-server[""",""" open """]
  Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
    """({activity}open) "+({file_path}({file_parent}[^"]*?[\\\/]+)?\s*({file_name}[^"\\\/]*?(\.({file_ext}\w+))?))"+""",
    """flags ({accesses}.+?) mode"""
	]
  }
```