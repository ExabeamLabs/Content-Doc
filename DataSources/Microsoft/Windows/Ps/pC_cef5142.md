#### Parser Content
```Java
{
Name = cef-5142
    Conditions = [ "|Microsoft|Microsoft Windows|", "A network share object was added", "Microsoft-Windows-Security-Auditing:5142|" ]
    Fields = ${WinParserTemplates.windows-events-3.Fields} [
      """({event_name}A network share object was added)""",
      """({event_code}5142)""",
      ]

windows-events-3 = {
      Vendor = Microsoft
      Product = Windows
      Lms = ArcSight
      DataType = "share-access"
      TimeFormat = "epoch"         
      Fields = [
        """\Wrt=({time}\d{1,100})""",
        """\sagt=({src_ip}[A-Fa-f0-9.:]{1,2000})""",
        """\Wdhost=\s{0,100}({dest_host}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
        """\sahost=({host}[^\s]{1,2000})""",
        """\Wdst=({dest_ip}[A-Fa-f0-9.:]{1,2000})""",
        """\Wdntdom=({domain}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
        """\Wduser=\s{0,100}({user}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
        """\Wduid=({login_id}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
        """\WfilePath=(?:\\+\*\\+)?({share_name}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
        """\Wad\.ShareLocalPath=(?:[\\\?]{1,2000})?(?:\s{0,100}|({share_path}({d_parent}.*?)({d_name}[^\\]{1,2000}?))(\\+)?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
        """\said=({aid}[^\s\\]{1,2000})""",
        """categoryOutcome=\/({outcome}[^\s]{1,2000})"""
        ]
     }

json-windows-events-1 = {
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]{1,2000}\s""",
    """"{1,20}created"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s\w+=""",
    """({event_name}An account was logged off)""",
    """"keywords"{1,20}:\["{1,20}({outcome}[^"]{1,2000})""",
    """"pid"{1,20}:({pid}\d{1,100})""",
    """thread"{1,20}:[^@]{1,2000}?"{1,20}id"{1,20}:({thread_id}\d{1,100})""",
    """"TargetUserName"{1,20}:"{1,20}(None|({target_user}[^"]{1,2000}))""",
    """"TargetDomainName"{1,20}:"{1,20}({domain}[^"]{1,2000})""",
    """"TargetLogonId"{1,20}:"{1,20}({logon_id}[^"]{1,2000})""",
    """"LogonType"{1,20}:"{1,20}({logon_type}[^"]{1,2000})""",
    """"TargetUserSid"{1,20}:"{1,20}({user_sid}[^"<,]{1,2000})""",
    """"record_id"{1,20}:({record_id}\d{1,100})""",
    """"task"{1,20}:"{1,20}({task_name}[^"]{1,2000})""",
    """"event_id"{1,20}:({event_code}\d{1,100})""",
    """"(?:winlog\.)?computer_name"{1,20}:"{1,20}({src_host}[^"]{1,2000})""",
    """"hostname"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"action"{1,20}:"{1,20}({action}[^"]{1,2000})""",
    """"os":[^@]{1,2000}?"name":"({os}[^"]{1,2000})""",
    """"SubjectLogonId"{1,20}:"{1,20}({logon_id}[^"]{1,2000})""",
    """"{1,20}activity_id"{1,20}:"{1,20}\{({activity_id}[^}]{1,2000})""",
    """"{1,20}ProviderName"{1,20}:"{1,20}({provider_name}[^"]{1,2000})""",
    """"{1,20}SubjectUserSid"{1,20}:"{1,20}({user_sid}[^"<,]{1,2000})""",
    """"{1,20}SubjectDomainName"{1,20}:"{1,20}({domain}[^"]{1,2000})""",
    """"user"{1,20}:"{1,20}(SYSTEM|-|({user}[^@"]{1,2000}))""",
    """"{1,20}SubjectUserName"{1,20}:"{1,20}(SYSTEM|-|({user}[^"]{1,2000}))""",
    """"{1,20}PrivilegeList"{1,20}:"{1,20}(-|({privileges}[^"]{1,2000}))""",
    """"{1,20}SidHistory"{1,20}:"{1,20}(-|({sid_history}[^"]{1,2000}))""",
    """"Keywords":"({outcome}[^"]{1,2000})"""
  ]
  DupFields = ["event_id->event_code"
}
```