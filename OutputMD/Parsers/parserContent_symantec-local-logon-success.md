#### Parser Content
```Java
{
Name = symantec-local-logon-success
  DataType = "local-logon"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """User Logged in""" ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """({outcome}(S|s)uccess)""",
    """({event_name}User Logged in)"""
  ]
}
```