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
symantec-critical-sys-protection = {
  Vendor = Symantec
  Product = Symantec Critical System Protection
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Fields = [
    """\sHOSTNAME\s*:\s*"+\s*({host}[^\s"]+)""",
    """\sEVENT_DT\s*:\s*"+({time}[^"]+)""",
    """\sUSER_NAME\s*:\s*"+({user}[^"\s]+)""",
    """\sRULE_NAME\s*:\s*"+({rule}[^"\s]+)""",
    """\sPOLICY_NAME\s*:\s*"+\s*({policy}[^"]+?)\s*"+?\s[^:]+:"""
    """\sPROCESS_PATH\s*:\s*"+({process_name}[^"\s]+)""",
    """SESSION_ID\s*:\s*"+({session_id}\d+)""",
    """Type of login\s*:\s*"*({logon_type}[^"]+)""",
    """Parent Name\s*:\s*({parent_process}[^\s"]+)""",
    """\sEVENT_ID:\s*"+({event_code}\d+)""",
    """\sHOSTADDR:\s*"+({dest_ip}[^"\s]+)""",
    """\sSVA_IP_ADDRESS:\s*"+({src_ip}[^"\s]+)""",
  ]

```