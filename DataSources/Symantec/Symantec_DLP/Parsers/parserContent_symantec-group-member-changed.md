#### Parser Content
```Java
{
Name = symantec-group-member-changed
DataType = "config-change"
Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """Group_Membership_Changed""" ]
Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
  """({event_name}Group_Membership_Changed)""",
  """Group Membership for "{1,20}({user}[^\s"]+)"{1,20} CHANGED from\s{1,100}'*({old_attribute}.+?)\s{0,100}to\s{0,100}'*({new_attribute}[^'"]+)"""
]
}
symantec-critical-sys-protection = {
  Vendor = Symantec
  Product = Symantec Critical System Protection
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Fields = [
    """\sHOSTNAME\s{0,100}:\s{0,100}"{1,20}\s{0,100}({host}[^\s"]+)""",
    """\sEVENT_DT\s{0,100}:\s{0,100}"{1,20}({time}[^"]+)""",
    """\sUSER_NAME\s{0,100}:\s{0,100}"{1,20}({user}[^"\s]+)""",
    """\sRULE_NAME\s{0,100}:\s{0,100}"{1,20}({rule}[^"\s]+)""",
    """\sPOLICY_NAME\s{0,100}:\s{0,100}"{1,20}\s{0,100}({policy}[^"]+?)\s{0,100}"{1,20}?\s[^:]+:"""
    """\sPROCESS_PATH\s{0,100}:\s{0,100}"{1,20}({process_name}[^"\s]+)""",
    """SESSION_ID\s{0,100}:\s{0,100}"{1,20}({session_id}\d{1,100})""",
    """Type of login\s{0,100}:\s{0,100}"{0,20}({logon_type}[^"]+)""",
    """Parent Name\s{0,100}:\s{0,100}({parent_process}[^\s"]+)""",
    """\sEVENT_ID:\s{0,100}"{1,20}({event_code}\d{1,100})""",
    """\sHOSTADDR:\s{0,100}"{1,20}({dest_ip}[^"\s]+)""",
    """\sSVA_IP_ADDRESS:\s{0,100}"{1,20}({src_ip}[^"\s]+)""",
  ]

```