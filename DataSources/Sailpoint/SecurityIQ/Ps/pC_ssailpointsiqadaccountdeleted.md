#### Parser Content
```Java
{
Name = s-sailpointsiq-ad-account-deleted
  DataType = "account-deleted"
  Conditions = ["""| applicationtype : Active Directory |""", """actiontype : Delete""", """| objectclass : user |"""]
  
  Fields = ${SailPointSIQADTemplates.s-sailpointsiqad-activity.Fields} [
    """objectcn\s:\s({target_user}[^|]{1,2000})\s\|"""
  ]
  DupFields = [ "host->src_host" ]
}
s-sailpointsiqad-activity = {
  Vendor = Sailpoint
  Product = SecurityIQ
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """servername\s:\s({host}[^|]{1,2000})\s\|""",
    """userfullname\s:\s({user_sid}(?=[^\\]{1,2000}\\)({domain}[^\\]{1,2000})\\({user}.+?)|(?:.+?))\s\|""",
    """actiontype\s:\s({event_name}[^|]{1,2000})\s\|""",
    """originatingserver\s:\s({host}[^|]{1,2000})\s\|"""
  ]

```