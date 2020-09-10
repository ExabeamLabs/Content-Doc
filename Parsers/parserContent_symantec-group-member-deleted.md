#### Parser Content
```Java
{
Name = symantec-group-member-deleted
  DataType = "member-removed"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """Group_Deleted""" ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """({outcome}(S|s)uccessful)"""
    """({event_name}Group_Deleted)""",
    """({new_attribute}Removed Entry: [^"]+)""",
    """"+Group "+({group_name}[^"]+)"+ REMOVED from\s*({object}[^\s"]+)""",
    """({outcome}(S|s)uccess)""",
  ]
}
```