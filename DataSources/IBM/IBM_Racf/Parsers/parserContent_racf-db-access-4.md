#### Parser Content
```Java
{
Name = racf-db-access-4
  DataType = "database-access"
  Conditions = [ """EVNTPRODESCR=VANGUARD_ACTIVE_ALERTS""", """EVNTNAME=ALTUSER""", """EVNTTEXT=Successful""" ]
  Fields = ${IBMracfParserTemplates.ibm-racf-activity.Fields} [
  ]
}
```