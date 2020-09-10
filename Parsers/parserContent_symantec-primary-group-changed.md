#### Parser Content
```Java
{
Name = symantec-primary-group-changed
DataType = "config-change"
Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """User_Primary_Group_Changed""" ]
Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
  """({event_name}User_Primary_Group_Changed)""",
  """User Primary Group ID for "+({user}[^\s"]+)"+ CHANGED from .+ in ({object}[^\s"]+)"*""",
  """({old_attribute}Old Entry: [^\s]+)""",
  """({new_attribute}New Entry: [^"]+)"""
]
  DupFields = ["object->group_name"]
}
```