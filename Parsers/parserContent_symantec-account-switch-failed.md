#### Parser Content
```Java
{
Name = symantec-account-switch-failed
  DataType = "account-switch"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """failed SU to """ ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """To Username:\s*({account}[^"\s]+)""",
    """({outcome}(F|f)ailed)""",
    """Event source:\s*({process_name}[^"]+?)\s*From""",
    """({event_name}failed SU to [^"]+?)\s*Event"""
  ]
}
```