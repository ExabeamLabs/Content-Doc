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
    """EVENT_DT:\s"{1,20}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d)"""",
    """\sHOSTADDR:\s"{1,20}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """\sHOSTNAME:\s{1,100}"{1,20}({host}[^"]{1,2000})"{1,20}\s""",
    """\sSession\s-\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s-\sLogging in as '(({domain}\w+)\\)?({user}\S+)'.""",
    """\sDESCRIPTION:\s"{1,20}({description}[^"]{1,2000})"""",
    """\sRULE_NAME: "{0,20}({rule_name}[^"]{1,2000})"""",
    """\sDOMAIN_NAME:\s{1,100}"{1,20}(unknown|null|({domain}[^"]{1,2000}))"{1,20}\s""",
    """\sEVENT_TYPE_D:\s{1,100}"{1,20}({event_name}[^"]{1,2000})"{1,20}\s""",
    """\sEVENT_SEVERITY_D:\s{1,100}"{1,20}({alert_severity}[^"]{1,2000})"{1,20}\s""",
    """\sEVENT_PRIORITY:\s{1,100}"{1,20}({priority}[^"]{1,2000})"{1,20}\s""",
    """\sPOLICY_NAME:\s{1,100}"{1,20}({policy}[^"]{1,2000})"{1,20}\s""",
    """\sPROCESS_NAME:\s{1,100}"{1,20}(unknown|null|({process}[^"]{1,2000}))"{1,20}\s""",
    """\sUSER_NAME:\s{1,100}"{1,20}(unknown|null|({user}[^"]{1,2000}))"{1,20}\s"""
  ]
  DupFields = [ "event_name->event_type" ]
}
```