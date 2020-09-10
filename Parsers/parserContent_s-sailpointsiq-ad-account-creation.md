#### Parser Content
```Java
{
Name = s-sailpointsiq-ad-account-creation
  DataType = "account-creation"
  Conditions = ["""| applicationtype : Active Directory |""", """actiontype : Create""", """| objectclass : user |"""]
  
  Fields = ${SailPointSIQADTemplates.s-sailpointsiqad-activity.Fields} [
    """objectcn\s:\s({account_name}[^|]+)\s\|"""
  ]
  DupFields = [ "host->dest_host", "domain->account_used_domain", "user->account" ]
}
```