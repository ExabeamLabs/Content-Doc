#### Parser Content
```Java
{
Name = racf-db-failed-login
  DataType = "database-login"
  Conditions = [ """EVNTPRODESCR=VANGUARD_ACTIVE_ALERTS""", """EVNTNAME=Signon""", """EVNTTIME=""", "EVNTDATE=""" ]
  Fields = ${IBMracfParserTemplates.ibm-racf-activity.Fields} [
   ]
   DupFields = ["additional_info->reason"]
}
```