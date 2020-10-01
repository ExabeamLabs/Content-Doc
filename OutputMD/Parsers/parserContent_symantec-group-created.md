#### Parser Content
```Java
{
Name = symantec-group-created
DataType = "member-added"
Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """Group_Created""" ]
Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
  """({event_name}Group_Created)""",
  """"+Group "+({group_name}[^"]+)"+ ADDED to\s*({object}[^\s"]+)""",
  """({new_attribute}New Entry: [^"]+)""",
]
}
```