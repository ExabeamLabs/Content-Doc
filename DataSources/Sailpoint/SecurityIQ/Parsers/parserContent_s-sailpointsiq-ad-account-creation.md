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
s-sailpointsiqad-activity = {
  Vendor = Sailpoint
  Product = SecurityIQ
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """servername\s:\s({host}[^|]+)\s\|""",
    """userfullname\s:\s({user_sid}(?=[^\\]+\\)({domain}[^\\]+)\\({user}.+?)|(?:.+?))\s\|""",
    """actiontype\s:\s({event_name}[^|]+)\s\|""",
    """originatingserver\s:\s({host}[^|]+)\s\|"""
  ]

```