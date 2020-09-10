#### Parser Content
```Java
{
Name = symantec-account-member-added
  DataType = "member-added"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """User_Created""" ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """({outcome}(S|s)uccessful)"""
    """({event_name}User_Created)""",
    """({new_attribute}New Entry: [^"]+)""",
    """ADDED to\s*({object}[^\s]+)""",
    """User "+({user}[^"]+)"+ ADDED to\s*({object}[^\s]+)""",
    """({outcome}(S|s)uccess)""",
  ]
  DupFields = ["object->group_name"]
}
```