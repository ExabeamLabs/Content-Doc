#### Parser Content
```Java
{
Name = s-sailpointsiq-windowsfs-perm-remove-file
  DataType = "file-operations"
  Conditions = ["""| applicationtype : Windows File Server (Agent) |""", """actiontype : Permission Remove File"""]
  
  Fields = ${SailPointSIQWindowsFSTemplates.s-sailpointsiqwindowsfs-activity.Fields} [
    """objectname\s:\s({file_name}[^|]+)\s\|""",
    """actiontype\s:\sPermission\s({accesses}[^|]+)\sFile\s\|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|"""
  ]
  DupFields = [ "host->dest_host" ]
}
```