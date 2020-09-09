#### Parser Content
```Java
{
Name = symantec-account-member-removed
  DataType = "member-removed"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """User_Deleted""" ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """({outcome}(S|s)uccessful)"""
    """({event_name}User_Deleted)""",
    """({new_attribute}New Entry: [^"]+)""",
    """User "+({user}[^"]+)"+ REMOVED from\s*({object}[^\s]+)""",
    """({outcome}(S|s)uccess)""",
  ]
  DupFields = ["object->group_name"]
}
```