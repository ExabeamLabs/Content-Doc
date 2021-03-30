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