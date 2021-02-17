#### Parser Content
```Java
{
Name = s-sailpointsiq-netappcifs-file-delete
  DataType = "file-operations"
  Conditions = ["""| applicationtype : Netapp - CIFS |""", """actiontype : Delete File"""]
  
  Fields = ${SailPointSIQNetAppCIFSTemplates.s-sailpointsiqnetappcifs-activity.Fields} [
    """objectname\s:\s({file_name}[^|]+)\s\|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|""",
    """actiontype\s:\s({event_name}[^|]+)\sFile\s\|"""
  ]
  DupFields = [ "host->dest_ip" ]
}
```