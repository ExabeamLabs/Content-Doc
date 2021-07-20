#### Parser Content
```Java
{
Name = symantec-local-logon-success
  DataType = "local-logon"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """User Logged in""" ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """({outcome}(S|s)uccess)""",
    """({event_name}User Logged in)""",
  ]
}
symantec-critical-sys-protection = {
    Vendor = Symantec
    Product = Symantec Critical System Protection
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
    Fields = [
      """\sHOSTNAME\s{0,100}:\s{0,100}"{1,20}({host}[^\s"]{1,2000})""",
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
      """\sDOMAIN_NAME\s{0,100}:\s{0,100}"{1,20}({domain}[^"\s]{1,2000})""",
    ]

```