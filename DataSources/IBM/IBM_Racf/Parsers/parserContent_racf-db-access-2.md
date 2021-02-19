#### Parser Content
```Java
{
Name = racf-db-access-2
  DataType = "database-access"
  Conditions = [ """EVNTPRODESCR=VANGUARD_ACTIVE_ALERTS""", """EVNTNAME=CONNECT""", """EVNTTEXT=Successful""" ]
  Fields = ${IBMracfParserTemplates.ibm-racf-activity.Fields} [
  ]
}
```