#### Parser Content
```Java
{
Name = s-sailpointsiq-windowsfs-member-removed
  DataType = "member-removed"
  Conditions = ["""| applicationtype : Windows File Server (Agent) |""", """actiontype : Member Removed"""]
  
  Fields = ${SailPointSIQWindowsFSTemplates.s-sailpointsiqwindowsfs-activity.Fields} [
        """objectname\s:\s({group_id}(?=[^\\]+\\)({group_domain}[^\\]+)\\({group_name}.+?)|(?:.+?)) \|"""
  ]
  DupFields = [ "host->dest_host" ]
}
```