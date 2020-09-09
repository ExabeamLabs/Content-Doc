#### Parser Content
```Java
{
Name = s-sailpointsiq-windowsfs-member-added
  DataType = "member-added"
  Conditions = ["""| applicationtype : Windows File Server (Agent) |""", """actiontype : Member Added"""]
  
  Fields = ${SailPointSIQWindowsFSTemplates.s-sailpointsiqwindowsfs-activity.Fields} [
    """objectname\s:\s({group_id}(?=[^\\]+\\)({group_domain}[^\\]+)\\({group_name}.+?)|(?:.+?)) \|"""
  ]
  DupFields = [ "host->dest_host", "domain->account_used_domain", "user->account", "sid_user->account_name" ]
}
```