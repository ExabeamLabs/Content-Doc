#### Parser Content
```Java
{
Name = remotelyanywhere-remote-login
  Vendor = LogMeIn
  Product = RemotelyAnywhere
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """"Windows_Remotely_Anywhere_Policy""", """ POLICY_NAME: """, """RA_Login_Success""" ]
  Fields = [
    """EVENT_DT:\s"+({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d)"""",
    """\sHOSTADDR:\s"+({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """\sHOSTNAME:\s+"+({host}[^"]+)"+\s""",
    """\sSession\s-\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s-\sLogging in as '(({domain}\w+)\\)?({user}\S+)'.""",
    """\sDESCRIPTION:\s"+({description}[^"]+)"""",
    """\sRULE_NAME: "*({rule_name}[^"]+)"""",
    """\sDOMAIN_NAME:\s+"+(unknown|null|({domain}[^"]+))"+\s""",
    """\sEVENT_TYPE_D:\s+"+({event_name}[^"]+)"+\s""",
    """\sEVENT_SEVERITY_D:\s+"+({alert_severity}[^"]+)"+\s""",
    """\sEVENT_PRIORITY:\s+"+({priority}[^"]+)"+\s""",
    """\sPOLICY_NAME:\s+"+({policy}[^"]+)"+\s""",
    """\sPROCESS_NAME:\s+"+(unknown|null|({process}[^"]+))"+\s""",
    """\sUSER_NAME:\s+"+(unknown|null|({user}[^"]+))"+\s"""
  ]
  DupFields = [ "event_name->event_type" ]
}

${SymantecParserTemplates.symantec-critical-sys-protection}{
  Name = symantec-local-logon-failed
  DataType = "local-logon"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """Failed Login""" ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """({outcome}(F|f)ailed)""",
    """({event_name}Failed Login)"""
  ]
}
```