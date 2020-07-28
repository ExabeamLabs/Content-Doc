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

{
  Name = ssh-remote-logon
  Vendor = Linux
  Product = SSH
  Lms = Splunk
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """SSH_Logon_""", """USER_TEXT: """, """COLLECTORNAME: """, """ ASSET_COLLECTORRID: """, """SVA_IP_ADDRESS: """ ]
  Fields = [
    """EVENT_DT:\s"+({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d)"""",
    """\sHOSTADDR:\s"+({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """\sHOSTNAME:\s+"+({host}[^"]+)"+\s""",
    """Remote From:\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sDESCRIPTION:\s"+({description}[^"]+)"""",
    """OSTYPE_D:\s"+({os}[^"]+)"+\s""",
    """Session id:\s*({session_id}\d+)""",
    """Process Name:\s*(null|unknown|({process_name}\S+))""",
    """Parent Name:\s*(null|unknown|({parent_process_name}\S+))""",
    """Username:\s*({user}\S+)""",
    """Port:\s*({src_port}\d+)""",
    """\sRULE_NAME: "*({rule_name}[^"]+)"""",
    """EVENT_TYPE_D:\s+"+({event_name}[^"]+)"+\s""",
    """EVENT_ID:\s+"+({logon_id}[^"]+)"+\s""",
    """PROCESS_ID:\s+"+(null|unknown|({pid}[^"]+))"+\s"""
  ]
  DupFields = [ "event_name->event_type" ]
}
{
  Name = accessit-badge-access
  Vendor = AccessIT
  Product = Universal.NET
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy.MM.dd.HH.mm.ss"
  Conditions = [ """"globallyuniqueeventid":""", """"cardholderlink":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"globallyuniqueeventid":"({time}\d\d\d\d.\d\d.\d\d.\d\d.\d\d.\d\d)""",
    """"cardnumber":({badge_id}\d+)""",
    """"accountname":"({user}[^"]+)""",
    """"cardholder":"({last_name}[^,]+),\s({first_name}[^"]+)""",
    """"eventlocation":"({location_door}[^"]+)""",
    """"eventdescription":"({outcome}[^"]+)""",
  ]
}
```