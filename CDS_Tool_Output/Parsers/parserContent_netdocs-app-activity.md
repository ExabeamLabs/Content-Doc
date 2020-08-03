#### Parser Content
```Java
{
Name = netdocs-app-activity
  Vendor = NetDocs
  Product = NetDocs
  DataType = "app-activity"
  Lms = Direct
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """</activity>""", """<activity date="""", """<user id="""", """guid="""", """host="""", """name="""", """custom-condition-CONT-7666"""]
  Fields = [
    """<activity date="({time}\d\d\d\d-\d+-\d+T\d+:\d+:\d+)" name="(|({activity}[^"]+))" host="(|({host}[^"]+))" desc="(|({=activity}[^"]+))""""
    """<user id="(|({user_email}[^@"]+?@[^"]+)|({user}[^"]+))" guid="(|({guid}[^"]+))" name="(|({user_fullname}[^"]+))""""
  ]
}

{
  Name = netdocs-file-operations
  Vendor = NetDocs
  Product = NetDocs
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<activity date="""", """<user id="""", """<storageObject""", """host="""", """name=""""]
  Fields = [
    """activity date="+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"+\sname""",
    """name="+({accesses}[^"]+)"+\shost""",
    """host="+({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """name="+({user}[^"]+)"+\smemberType""",
    """user\sid="+({user}[^"]+)"+\sname""",
    """name="+({file_name}[^"]+)"+\s(version|size)""",
    """size="+({file_size}[^"]+)"+\sfileExtension""",
    """fileExtension="+({file_ext}[^"]+)""""
  ]
  DupFields = [ "host->dest_ip" ]
}

{
  Name = cef-zlock-app-activity
  Vendor = Zlock
  Product = Zlock
  DataType = "app-activity"
  Lms = ArcSight
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""",  """|Zlock|"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({app}Zlock)""",
    """msg=({activity}.+?)\s+(\w+=|$)""",
    """suser=(({domain}[^\\]+)\\)?({user}[^\s\\]+)\s+(\w+=|$)""",
    """shost=({src_host}[^\s]+)\s+(\w+=|$)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """\srt=({time}\d+)""",
    """sproc=({process_name}[^\s]+)\s+(\w+=|$)""",
    """fsize=({file_size}\d+)""",
    """cs2=({device_name}.+?)\s+(\w+=|$)""",
    """cs3=({policy}.+?)\s+(\w+=|$)""",
    """\sdvc=({host}\S+)(\s+\w+=|\s*$)""",
    """\sdvchost=({host}\S+)(\s+\w+=|\s*$)""",
    """fname=({file_path}({file_parent}[^=]*?[\\\/]+)?({file_name}[^\\\/=]+?(\.({file_ext}\w+))?))\s+\w+="""
	]  
  DupFields = [ "file_name->object" ]
}

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