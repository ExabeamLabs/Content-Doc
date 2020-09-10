#### Parser Content
```Java
{
Name = symantec-group-member-changed
DataType = "config-change"
Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """Group_Membership_Changed""" ]
Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
  """({event_name}Group_Membership_Changed)""",
  """Group Membership for "+({user}[^\s"]+)"+ CHANGED from\s+'*({old_attribute}.+?)\s*to\s*'*({new_attribute}[^'"]+)"""
]
}
```