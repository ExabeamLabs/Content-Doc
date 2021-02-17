#### Parser Content
```Java
{
Name = s-sailpointsiq-windowsfs-file-read
  DataType = "file-operations"
  Conditions = ["""| applicationtype : Windows File Server (Agent) |""", """actiontype : Read File"""]
  
  Fields = ${SailPointSIQWindowsFSTemplates.s-sailpointsiqwindowsfs-activity.Fields} [
    """objectname\s:\s({file_name}[^|]+)\s\|""",
    """actiontype\s:\s({accesses}[^|]+)\sFile\s\|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|"""
  ]
  DupFields = [ "host->dest_host" ]
}
```