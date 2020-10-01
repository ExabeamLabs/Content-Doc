#### Parser Content
```Java
{
Name = s-sailpointsiq-ad-account-passwd-reset
  DataType = "password-change"
  Conditions = ["""| applicationtype : Active Directory |""", """actiontype : Reset Password""", """| objectclass : user |"""]
  
  Fields = ${SailPointSIQADTemplates.s-sailpointsiqad-activity.Fields} [
    """objectcn\s:\s({target_user}[^|]+)\s\|"""
  ]
}
```