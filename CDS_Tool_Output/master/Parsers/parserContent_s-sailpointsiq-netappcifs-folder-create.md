#### Parser Content
```Java
{
Name = s-sailpointsiq-netappcifs-folder-create
  DataType = "file-operations"
  Conditions = ["""| applicationtype : Netapp - CIFS |""", """actiontype : Create Folder"""]
  
  Fields = ${SailPointSIQNetAppCIFSTemplates.s-sailpointsiqnetappcifs-activity.Fields} [
    """objectname\s:\s({file_name}[^|]+)\s\|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|""",
	"""subjecttype\s:\s({file_type}[^|]+)\s""",
    """actiontype\s:\s({event_name}[^|]+)\sFolder\s\|"""
  ]
  DupFields = [ "host->dest_ip" ]
}
```