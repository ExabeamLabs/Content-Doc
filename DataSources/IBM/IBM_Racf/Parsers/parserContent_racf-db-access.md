#### Parser Content
```Java
{
Name = racf-db-access
  DataType = "database-access"
  Conditions = [ """EVNTPRODESCR=VANGUARD_ACTIVE_ALERTS""", """EVNTNAME=Access""", """EVNTTEXT=Failed due to PROTECTALL""" ]
  Fields = ${IBMracfParserTemplates.ibm-racf-activity.Fields} [
  ]
}
```