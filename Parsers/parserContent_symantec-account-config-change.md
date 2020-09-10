#### Parser Content
```Java
{
Name = symantec-account-config-change
  DataType = "config-change"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """User_Configuration_Changed""" ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """({outcome}(S|s)uccess)"""
    """User Password for "+({user}[^\s"]+)"+ CHANGED in\s*({object}[^"]+?)\s*Old""",
    """({event_name}User_Configuration_Changed)""",
    """({old_attribute}Old Entry: [^\s]+)""",
    """({new_attribute}New Entry: [^"]+)""",
  ]
}
```