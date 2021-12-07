#### Parser Content
```Java
{
Name = ad-json-member-removed-2008
  DataType = "windows-ds-access"
  Conditions = [""""event_id":""", """Microsoft-Windows-Security-Auditing""", """A member was removed from a security-enabled"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A member was removed from a security-enabled)""",
    """"{1,20}MemberSid"{1,20}:"{1,20}({account_id}[^"]{1,2000})""",
    """"TargetSid":"({group_id}[^\s"]{1,2000})"""
    """event_id"{1,20}:({event_code}\d{1,100})""",
  ]

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