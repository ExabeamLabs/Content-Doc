#### Parser Content
```Java
{
Name = racf-db-access-4
  DataType = "database-access"
  Conditions = [ """EVNTPRODESCR=VANGUARD_ACTIVE_ALERTS""", """EVNTNAME=ALTUSER""", """EVNTTEXT=Successful""" ]
  Fields = ${IBMracfParserTemplates.ibm-racf-activity.Fields} [
  ]
}
ibm-racf-activity = {
Vendor = IBM
Product = IBM Racf
Lms = Splunk
TimeFormat = "yyyy-MM-dd HH:mm:ss"
Fields = [
  """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
  """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
  """APPLSIEMVRM=({host}[^=]{1,2000}?)\s\w+=""",
  """APPLHOSTIPADD=({host_ip}[A-Fa-f.:\d]{1,2000})""",
  """EVNTUSERID=({db_user}[^=]{1,2000}?)\s\w+=""",
  """EVNTNAME=({event_name}[^=]{1,2000}?)\s\w+=""",
  """EVNTUSERNAME=(\-*N\/A\-*|({user}[^=]{1,2000}?))\s\w+=""",
  """EVNTTEXT=({additional_info}[^=]{1,2000}?)\s\w+=""",
  """EVNTCOMMAND=(\-*N\/A\-*|({db_query}[^=]{1,2000}?))(\s\w+=|\s{0,100}$)""",
  """EVNTCLASSNAME=(\-*N\/A\-*|({database_object}[^=]{1,2000}?))\s{0,100}\w+="""
  ]

```