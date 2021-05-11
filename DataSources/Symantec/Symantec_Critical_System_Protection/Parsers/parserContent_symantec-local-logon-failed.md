#### Parser Content
```Java
{
Name = symantec-local-logon-failed
  DataType = "local-logon"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """Failed Login""" ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """({outcome}(F|f)ailed)""",
    """({event_name}Failed Login)"""
  ]
}
symantec-critical-sys-protection = {
    Vendor = Symantec
    Product = Symantec Critical System Protection
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
    Fields = [
      """\sHOSTNAME\s{0,100}:\s{0,100}"{1,20}({host}[^\s"]+)""",
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
      """\sDOMAIN_NAME\s{0,100}:\s{0,100}"{1,20}({domain}[^"\s]+)""",
    ]

```