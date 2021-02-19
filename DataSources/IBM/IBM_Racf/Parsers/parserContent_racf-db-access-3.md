#### Parser Content
```Java
{
Name = racf-db-access-3
  DataType = "database-access"
  Conditions = [ """EVNTPRODESCR=VANGUARD_ACTIVE_ALERTS""", """EVNTNAME=SETROPTS""", """EVNTTEXT=Successful""" ]
  Fields = ${IBMracfParserTemplates.ibm-racf-activity.Fields} [
  ]
}
```