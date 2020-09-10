#### Parser Content
```Java
{
Name = s-sailpointsiq-windowsfs-perm-remove-folder
  DataType = "file-operations"
  Conditions = ["""| applicationtype : Windows File Server (Agent) |""", """actiontype : Permission Remove Folder"""]
  
  Fields = ${SailPointSIQWindowsFSTemplates.s-sailpointsiqwindowsfs-activity.Fields} [
    """objectname\s:\s({file_name}[^|]+)\s\|""",
    """actiontype\s:\sPermission\s({accesses}[^|]+)\sFolder\s\|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|""",
    """subjecttype\s:\s({file_type}[^|]+)\s\|"""
  ]
}
```