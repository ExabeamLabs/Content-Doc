#### Parser Content
```Java
{
Name = symantec-local-logon-failed
  DataType = "local-logon"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """Failed Login""" ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """({outcome}(F|f)ailed)""",
    """({event_name}Failed Login)"""
  ]
}
```