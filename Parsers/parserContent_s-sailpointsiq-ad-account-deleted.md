#### Parser Content
```Java
{
Name = s-sailpointsiq-ad-account-deleted
  DataType = "account-deleted"
  Conditions = ["""| applicationtype : Active Directory |""", """actiontype : Delete""", """| objectclass : user |"""]
  
  Fields = ${SailPointSIQADTemplates.s-sailpointsiqad-activity.Fields} [
    """objectcn\s:\s({target_user}[^|]+)\s\|"""
  ]
  DupFields = [ "host->src_host" ]
}
```