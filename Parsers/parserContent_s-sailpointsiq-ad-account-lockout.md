#### Parser Content
```Java
{
Name = s-sailpointsiq-ad-account-lockout
  DataType = "account-lockout"
  Conditions = ["""| applicationtype : Active Directory |""", """actiontype : Account Lock""", """| objectclass : user |"""]
  
  Fields = ${SailPointSIQADTemplates.s-sailpointsiqad-activity.Fields} [
    """extradetails\s:\sCaller Computer Name::[\W]*({dest_host}[^|]+)\s\|"""
  ]
}
```