#### Parser Content
```Java
{
Name = symantec-account-config-change
  DataType = "config-change"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """User_Configuration_Changed""" ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """({outcome}(S|s)uccess)"""
    """User Password for "{1,20}({user}[^\s"]{1,2000})"{1,20} CHANGED in\s{0,100}({object}[^"]{1,2000}?)\s{0,100}Old""",
    """({event_name}User_Configuration_Changed)""",
    """({old_attribute}Old Entry: [^\s]{1,2000})""",
    """({new_attribute}New Entry: [^"]{1,2000})""",
  ]
}
symantec-critical-sys-protection = {
  Vendor = Symantec
  Product = Symantec Critical System Protection
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Fields = [
    """\sHOSTNAME\s{0,100}:\s{0,100}"{1,20}\s{0,100}({host}[^\s"]{1,2000})""",
    """\sEVENT_DT\s{0,100}:\s{0,100}"{1,20}({time}[^"]{1,2000})""",
    """\sUSER_NAME\s{0,100}:\s{0,100}"{1,20}({user}[^"\s]{1,2000})""",
    """\sRULE_NAME\s{0,100}:\s{0,100}"{1,20}({rule}[^"\s]{1,2000})""",
    """\sPOLICY_NAME\s{0,100}:\s{0,100}"{1,20}\s{0,100}({policy}[^"]{1,2000}?)\s{0,100}"{1,20}?\s[^:]{1,2000}:"""
    """\sPROCESS_PATH\s{0,100}:\s{0,100}"{1,20}({process_name}[^"\s]{1,2000})""",
    """SESSION_ID\s{0,100}:\s{0,100}"{1,20}({session_id}\d{1,100})""",
    """Type of login\s{0,100}:\s{0,100}"{0,20}({logon_type}[^"]{1,2000})""",
    """Parent Name\s{0,100}:\s{0,100}({parent_process}[^\s"]{1,2000})""",
    """\sEVENT_ID:\s{0,100}"{1,20}({event_code}\d{1,100})""",
    """\sHOSTADDR:\s{0,100}"{1,20}({dest_ip}[^"\s]{1,2000})""",
    """\sSVA_IP_ADDRESS:\s{0,100}"{1,20}({src_ip}[^"\s]{1,2000})""",
  ]

```