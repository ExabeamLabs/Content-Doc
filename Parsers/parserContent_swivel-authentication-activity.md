#### Parser Content
```Java
{
Name = swivel-authentication-activity
  Vendor = Swivel
  Product = Swivel
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [""" INFO """, """ PINsafe[""", """]: """]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """user[:\s]*({user}[^\s.,]+)""",
    """({app}PINsafe)""",
    """\d\d:\d\d:\d\d\s({host}[a-fA-F\d.:]+)""",
    """INFO\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(-\s+)?({activity}.+?)\s*$""",
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d+)\s+({activity}.+?)\s*$"""
	]
}

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
    """<user id="(|({user_email}[^@"]+?@({email_domain}[^"]+))|({user}[^"]+))" guid="(|({guid}[^"]+))" name="(|({user_fullname}[^"]+))""""
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